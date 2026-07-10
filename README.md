# BusyNCR

Versioned backup tool for Windows hosts: a client (Windows service) ships
content-defined, client-side-encrypted chunks to a self-hosted daemon over
mTLS gRPC. Snapshots thin out over time on an exponential retention grid
(3 h → 24 h → 4 d → 16 d) with cheap arbitrary-version pruning via
content-addressed storage. An interactive visualization of how the retention
grid thins snapshots over time: https://heios.github.io/busyncr/visual-grid/

Built autonomously, slice by slice — see PRD.md (destination), SLICES.md
(map), AGENTS.md (rules of the road). See CHANGELOG.md for what shipped in
each slice.

## Quickstart

Two binaries, one workspace: `busyncr-daemon` (backup server) and
`busyncr-client` (the host being backed up). This walks the full lifecycle —
daemon setup, enrollment, chunk-size sizing, backup, restore, and migrating
to a new machine — using the CLI exactly as it exists at the end of S13.
Every subcommand also has full `--help` text; this is the short path through
it.

### 1. Start the daemon

```sh
busyncr-daemon serve --store /var/lib/busyncr --listen 0.0.0.0:47820
```

First run bootstraps an internal CA and server certificate under
`/var/lib/busyncr/identity/` (PRD §3.4) and starts serving mTLS gRPC. Leave
it running (it is a long-lived process — see PRD §3.6 for the Windows
service story on the *client* side; the daemon itself is a plain foreground
process you supervise however you like: systemd, a container, etc.).

### 2. Mint an enrollment token and enroll the client

On the daemon host:

```sh
busyncr-daemon enroll-token --store /var/lib/busyncr
```

This prints a one-time token, the CA certificate's path, and the exact
`busyncr-client enroll` command to run. Copy `ca-cert.pem` to the client
host, then on the client:

```sh
busyncr-client enroll \
  --daemon https://backup-server:47820 \
  --ca ca-cert.pem \
  --token <token-from-above> \
  --name my-laptop \
  --state C:\ProgramData\busyncr
```

This generates a local keypair (the private key never leaves the machine),
receives a CA-signed client certificate, and — on first enrollment only —
creates the backup set's data key (`data.key`) **and** its keyed chunk-ID
key (`chunk-id.key`), both in the state directory. The chunk-ID key is what
makes chunk identity `blake3::keyed_hash(chunk_id_key, plaintext)` instead
of plain BLAKE3 (FR-K1): a daemon that already possesses a candidate file
cannot chunk+hash it and check the store for a match, closing that
known-plaintext confirmation channel. It costs nothing in practice — dedup
still works exactly the same across every backup made with the same
keyfile — but it does mean dedup scope is per-backup-set (per key) rather
than daemon-global. **Immediately run `export-key` (step 6) and store the
keyfile off this machine.** Losing the state directory without an exported
keyfile means losing access to every backup ever made (PRD §3.4 — the
daemon is zero-knowledge and cannot recover it for you).

### 3. Pick a chunk size with `bench-chunking`

Before the first backup, measure real dedup/storage trade-offs on your own
data instead of guessing (PRD §3.7):

```sh
busyncr-client bench-chunking C:\Users\alex\Documents --sizes 256K,512K,1M,2M,4M
```

This reads every file exactly once, fans the byte stream out to one
content-defined chunker per candidate size, and reports (per candidate)
total/unique chunks, the intra-dataset dedup ratio, chunk-size percentiles,
and exact projected daemon-index + manifest bookkeeping for your retention
grid. Add `--baseline <older-copy-path>` to measure real cross-snapshot
chunk overlap instead of an intra-snapshot estimate, or `--json` for
machine-readable output. The table highlights a recommended size (smallest
`unique_bytes + projected_bookkeeping_bytes`); the choice is yours.

Commit the chosen size in the client config file:

```toml
# busyncr-client.toml
daemon = "https://backup-server:47820"
folders = ["C:/Users/alex/Documents", "D:/projects"]
chunk_target_size = "1M"   # from bench-chunking, above
```

(Skipping this step and passing `--default-chunking` to `backup`/`run`
accepts a 1 MiB default instead — fine for a quick start, but changing the
size later resets dedup continuity, so pick deliberately for real data.)

Optionally also measure compression trade-offs on the same data before
committing (see [Compression](#compression) below):

```sh
busyncr-client bench-chunking C:\Users\alex\Documents --sizes 1M --compression
```

### 4. Back up

```sh
busyncr-client backup --config busyncr-client.toml --state C:\ProgramData\busyncr
```

Walks every configured folder, chunks and client-side-encrypts changed
data, asks the daemon which chunks it already has (`HasChunks`), and ships
only the missing ones (FR2/FR3). Repeat this on a schedule with:

```sh
busyncr-client run --config busyncr-client.toml --state C:\ProgramData\busyncr --interval 3h
```

which backs up immediately and then every `--interval` (default 3 h) with
jitter, or install it as a proper Windows service (FR8, PRD §3.6):

```powershell
busyncr-client service install --config busyncr-client.toml --state C:\ProgramData\busyncr
busyncr-client service start
```

### 5. List history and restore

```sh
busyncr-client list --config busyncr-client.toml --state C:\ProgramData\busyncr
busyncr-client restore --config busyncr-client.toml --state C:\ProgramData\busyncr \
  01J... C:\restore-target
```

`restore` fetches the manifest and every chunk it references, decrypts,
verifies each chunk's content address against a corrupt/truncated blob
(FR9), and reassembles the tree byte-exact including mtime and permissions
(FR4). The target directory must be empty (it is created if missing).

### 6. Export the key, and migrate to a new machine

```sh
busyncr-client export-key --state C:\ProgramData\busyncr --output busyncr.keyfile
# store busyncr.keyfile (and its passphrase) OFF this machine
```

On a replacement machine: enroll fresh against the daemon (step 2, new
token, new certificate — identity is never migrated, PRD §3.4), then:

```sh
busyncr-client import-key --state C:\ProgramData\busyncr-new --keyfile busyncr.keyfile
busyncr-client list --config busyncr-client.toml --state C:\ProgramData\busyncr-new
busyncr-client restore --config busyncr-client.toml --state C:\ProgramData\busyncr-new \
  01J... C:\restore-target
```

The old machine's entire history is now visible and restorable from the new
one (FR6), and the new machine can keep backing up into the same set.

### Retention and garbage collection (daemon side)

```sh
busyncr-daemon prune --store /var/lib/busyncr
busyncr-daemon gc --store /var/lib/busyncr --grace-secs 3600
```

`prune` applies the PRD §3.5 retention grid (keep one per 3 h under 24 h,
one per 24 h under 4 d, one per 4 d under 16 d, one per 16 d beyond that —
newest survives in each cell) and drops over-retained manifests; `gc`
reclaims chunks that have had zero references for at least the grace
period, so a backup racing a GC never loses just-uploaded data (FR5).

## Compression

Every new unique chunk is compressed before encryption (FR-C1.md), controlled
by an optional `[compression]` table in the client config:

```toml
# busyncr-client.toml
[compression]
use_probe = false   # opt in to a cheap lz4 probe before zstd (probe+zstd3)
escalate = false    # opt in to a zstd-9 retry on well-compressing chunks
zstd_level = 3
escalate_level = 9
keep_threshold = 0.95    # keep compressed form iff compressed <= 0.95 * raw
probe_threshold = 1.02   # probe+zstd3: skip zstd below this probe ratio
escalate_ratio = 2.0     # +escalate: retry level 9 once zstd-3 beats this ratio
```

Omitting the table (or any field in it) keeps the baseline `zstd3` policy:
compress each chunk at zstd level 3, keep the compressed form only if it's
smaller than 95% of the raw size, otherwise store raw — the decision is made
from the actual compressed output, never guessed. `probe+zstd3` adds a fast
lz4 probe first and skips zstd entirely on chunks that don't look
compressible; its output is never stored (FR-C1 C1.4). `+escalate` retries a
well-compressing chunk at zstd level 9 and keeps whichever is smaller — this
is **hard-disabled during a backup set's first (initial full) backup**
regardless of config, since that's the only phase where compression sits on
the wall-clock critical path, and only ever runs on later incremental
backups (FR-C6).

The one-byte codec marker (raw/zstd) is prepended to the plaintext and
encrypted along with it (C1.1/C1.2) — the daemon never sees which codec was
used. Chunk identity is always the BLAKE3 (keyed, see above) of the
*uncompressed* plaintext (C1.3), so the compression decision never affects
dedup, protocol, or the store format: policies can change freely between
backups, and a mixed-codec history (some chunks raw, some zstd-3, some
escalated zstd-9, all in one manifest) restores byte-exact either way.

Before committing a policy, measure it on real data:

```sh
busyncr-client bench-chunking C:\Users\alex\Documents --sizes 1M --compression \
  --net-mbps 50,200,1000
```

This simulates five candidate policies (`raw-only`, `zstd3-always`, `zstd3`,
`probe+zstd3`, `zstd3+escalate`) over the real unique-chunk stream, reporting
per policy: total stored bytes and ratio, measured compression MB/s, and a
backup-speed projection (measured read/CDC/BLAKE3/compress throughput plus a
synthetic AEAD microbenchmark, combined per `--threads`) at the CPU-bound
floor and at each `--net-mbps` bandwidth point — the number to watch on slow
links, since a stronger policy multiplies effective upload bandwidth by its
ratio and can *speed up* a backup even though it costs more CPU. Add
`--baseline <older-copy-path>` to turn on the incremental-update row with
real new-chunk volume instead of an assumption. A recommended policy is
highlighted (smallest projected steady-state store among policies within
1.5x of `zstd3`'s CPU-bound time); the choice, like chunk size, stays with
you and belongs in config next to `chunk_target_size`. Full details:
`busyncr-client bench-chunking --help`.

## Threat model

- **Transport**: mutual TLS, per-machine certs issued by the daemon's
  internal CA; every RPC except enrollment requires a valid, non-revoked
  client cert (FR1).
- **At rest / zero-knowledge**: the daemon only ever sees chunk IDs and
  encrypted blobs. It cannot decrypt chunk contents or manifests (client-held
  data key, XChaCha20-Poly1305, FR7) and, as of FR-K1, it cannot even
  *confirm* whether a specific plaintext it already possesses is stored,
  because chunk identity is a keyed hash (`blake3::keyed_hash(chunk_id_key,
  plaintext)`) using a key it never receives — a daemon that chunks and
  hashes a candidate file itself gets zero matches against the real store
  (FR-K1b).
- **Compression is invisible in the ciphertext's structure**: the codec byte
  is encrypted along with the payload, so the daemon cannot distinguish raw
  from compressed chunks, or infer which compression policy is in effect
  (FR-C7).
- **Accepted leak, documented, not fixed**: ciphertext *length* still leaks
  coarse compressibility — a highly compressible chunk produces a
  measurably shorter blob than an incompressible one of the same original
  size, whether or not compression changed the plaintext's meaning. Padding
  or length-hiding would close this but is out of scope for both FR-C1 and
  FR-K1 (their explicit non-goal lists); an observer with full store access
  and a size histogram could distinguish compressible from incompressible
  data at the granularity of individual chunks, but this is exactly as true
  without compression (chunk sizes already vary) and reveals nothing about
  content beyond that coarse signal.
- **What stays out of scope in v1**: cross-client global dedup-recovery
  schemes (e.g. convergent encryption) are explicitly rejected — they would
  reintroduce the confirmation channel FR-K1 closes. Identity (certs) is
  never migrated between machines; only data (via keyfile export/import,
  FR6) is.

## Supported platforms

Release binaries (see the Releases page once versions are tagged) are as
statically linked as each OS allows — no runtime dependencies to install:

| Platform | Targets | Notes |
|---|---|---|
| Windows | x86_64, arm64 | static CRT — no VC++ Redistributable, no .NET |
| Linux | x86_64, arm64 | fully static (musl) — runs on any distro, no glibc needed |
| Linux | riscv64 (rv64gc) | **best-effort**: published when the build succeeds, but a riscv64 build failure never blocks a release, so a given version may ship without it |
| macOS | Apple Silicon (macOS 11+), Intel (10.13+) | links Apple system libraries only (ship with the OS) |

Exact minimum OS versions and the full dependency inventory will be
documented in REQUIREMENTS.md at the end of the current implementation cycle.
