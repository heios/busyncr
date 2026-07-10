# BusyNCR

Versioned backup tool for Windows hosts: a client (Windows service) ships
content-defined, client-side-encrypted chunks to a self-hosted daemon over
mTLS gRPC. Snapshots thin out over time on an exponential retention grid
(3 h → 24 h → 4 d → 16 d) with cheap arbitrary-version pruning via
content-addressed storage.

Built autonomously, slice by slice — see PRD.md (destination), SLICES.md
(map), AGENTS.md (rules of the road). Full docs land in slice S13.
