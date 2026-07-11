# BusyNCR — Platform requirements & dependency inventory

Status: verified 2026-07-10 against the v0.1.0-candidate tree (post S0–S13,
K1, C1–C4, M1). Runtime claims are enforced mechanically by the release
pipeline's linkage-verification gates (`.github/workflows/release.yml`):
`file`/`readelf` on Linux, `dumpbin /DEPENDENTS` on Windows, `otool -L` on
macOS — a release cannot publish if any claim below regresses.

## 1. Runtime requirements (what a user needs to run the binaries)

| Platform | Minimum OS | Runtime dependencies |
|---|---|---|
| Linux x86_64 | kernel ≥ 3.2, any distro | **none** — fully static musl binary (no glibc, no OpenSSL; verified: no `INTERP` header, `file` reports statically linked) |
| Linux arm64 (aarch64) | kernel ≥ 3.7, any distro | **none** — fully static musl binary |
| Linux riscv64 (rv64gc) | rv64gc-capable kernel/distro | **none** — fully static musl binary. **Best-effort target**: published when it builds; a given release may ship without it |
| Windows x86_64 | Windows 10 / Server 2016 | **none beyond Windows** — static CRT (verified: no VCRUNTIME/MSVCP/api-ms-win-crt imports). No VC++ Redistributable, no .NET (native code; the service integrates via Win32 SCM). TLS is in-binary (no Schannel dependency) |
| Windows arm64 | Windows 10 ARM64 / Windows 11 | same as x86_64 |
| macOS Apple Silicon | macOS 11 Big Sur | Apple system libraries only (`/usr/lib`, `/System/Library` — ship with the OS; verified via otool gate). Everything else statically embedded |
| macOS Intel | macOS 10.13 High Sierra (deployment target pinned) | same |

Both binaries (`busyncr-client`, `busyncr-daemon`) are built for every
platform above. Disk: the daemon store grows with retained history
(unbounded until FR-Q1 quota lands — see ROADMAP R7). Network: one TCP port
(default 47820) daemon-side; client needs outbound reach to it.

## 2. Statically embedded native code (inside the binaries)

| Component | Carrier crate (locked) | Role |
|---|---|---|
| AWS-LC (libcrypto) | `aws-lc-sys 0.42.0` | TLS/mTLS via rustls backend (tonic `tls-aws-lc`) |
| libzstd 1.5.7 | `zstd-sys 2.0.16+zstd.1.5.7` | chunk compression (FR-C1) |
| BLAKE3 optimized kernels | `blake3 1.8.5` | chunk identity (keyed, FR-K1) + integrity |
| ring (assembly) | `ring 0.17.14` | transitive crypto primitive dependency |

lz4 probing uses `lz4_flex 0.11.6` — pure Rust, nothing embedded; its output
is never stored (FR-C1 C1.4).

## 3. Key Rust dependencies (direct, per Cargo.lock)

Core logic: `fastcdc` (CDC chunking), `blake3`, `chacha20poly1305`
(XChaCha20-Poly1305 AEAD), `argon2` (keyfile KDF), `redb` (daemon index),
`ulid`, `serde`/`postcard`/`toml`/`serde_json`, `zstd`, `lz4_flex`.
Networking: `tonic`/`prost` 0.13 line (gRPC), `tokio`, `tokio-stream`,
`rcgen` (internal CA), rustls via tonic's `tls-aws-lc`.
CLI/plumbing: `clap`, `thiserror`, `anyhow`, `rand`, `filetime`, `tempfile`
(dev). Windows only: `windows-service`, `windows-sys`.
Exact versions: `Cargo.lock` (committed; the zstd pin matters for FR-C5b
exact-match tests).

## 4. Build-time requirements (contributors / from-source builds)

- Rust stable (built and CI-verified with 1.95; edition 2021).
- `protoc` is **vendored** (`protoc-bin-vendored`) — no system protobuf
  needed, build-time only, never shipped.
- C toolchain + CMake for `aws-lc-sys` (present on all GitHub runners).
- Linux static builds: `musl-tools` (x86_64 native) or `cross` (Docker-based,
  arm64/riscv64).
- Windows: MSVC toolchain (VS Build Tools), ARM64 cross tools for the arm64
  target; `RUSTFLAGS=-C target-feature=+crt-static` for redistributable-free
  binaries (release.yml sets this).
- macOS: Xcode CLT; `MACOSX_DEPLOYMENT_TARGET` 11.0 (arm64) / 10.13 (x86_64)
  as pinned in release.yml.

## 5. Verification provenance

Every runtime claim in §1 maps to a hard release gate: Linux —
`file`+`readelf -l` prove static (build fails on an `INTERP` header);
Windows — `dumpbin /DEPENDENTS` fails the build on any CRT import; macOS —
`otool -L` fails the build on any non-`/usr/lib`, non-`/System/Library`
dylib. OS floors derive from the Rust 1.95 tier definitions (Windows 10+,
macOS 10.12+/11+ arm64, kernel 3.2+) and the pinned deployment targets;
they are re-checked whenever the toolchain is upgraded.
