# BusyNCR

Versioned backup tool for Windows hosts: a client (Windows service) ships
content-defined, client-side-encrypted chunks to a self-hosted daemon over
mTLS gRPC. Snapshots thin out over time on an exponential retention grid
(3 h → 24 h → 4 d → 16 d) with cheap arbitrary-version pruning via
content-addressed storage.

Built autonomously, slice by slice — see PRD.md (destination), SLICES.md
(map), AGENTS.md (rules of the road). Full docs land in slice S13.

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
