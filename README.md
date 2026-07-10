# BusyNCR

Versioned backup tool for Windows hosts: a client (Windows service) ships
content-defined, client-side-encrypted chunks to a self-hosted daemon over
mTLS gRPC. Snapshots thin out over time on an exponential retention grid
(3 h → 24 h → 4 d → 16 d) with cheap arbitrary-version pruning via
content-addressed storage.

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
creates the backup set's data key (`data.key` in the state directory).
**Immediately run `export-key` (step 6) and store the keyfile off this
machine.** Losing the state directory without an exported keyfile means
losing access to every backup ever made (PRD §3.4 — the daemon is
zero-knowledge and cannot recover it for you).

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
