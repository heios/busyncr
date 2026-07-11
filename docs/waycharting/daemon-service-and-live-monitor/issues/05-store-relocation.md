# 05 — Store relocation: what "storage moving" ships as

- Type: grilling
- Status: open
- Blocked by: none

## Question

The owner listed "storage moving" as a first-production-run control need:
move the daemon's store to a new path/disk (e.g. the first disk fills up).
Decide the v1 shape:

1. **Is the store portable by construction?** Verify nothing in the index
   or identity dir records absolute paths; if true, a *cold move* (stop
   daemon → move directory → restart with new `--store` / config path) is
   already safe and mostly needs verification + documentation.
2. **Documented procedure vs tooling** — options by increasing cost:
   - a documented cold-move procedure with an integrity check to run after
     (`status` figures match pre-move ground truth; maybe a
     `verify-store` pass);
   - an assisted `busyncr-daemon move-store --to <path>` (copy → verify →
     atomically switch config → old dir left for manual deletion);
   - online migration (serve continues during the copy) — almost certainly
     out of scope; say so explicitly if confirmed.
3. **Service interplay** — after ticket 02, the store path lives in a
   service definition (plist/unit/SCM config); moving the store means
   updating that too. Does the procedure/tool own that update?

Resolution is a decision + procedure sketch; implementation slices come out
of ticket 07.
