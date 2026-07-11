# bench-chunking — owner's real workload, 2026-07-11

First real-workload benchmark, run by the owner on the Windows host.
Primary input for the chunk-size decision and the R8 packed-store-layout
effort. Verbatim output:

```text
bench-chunking: C:\DOCUMENTS\ — 277096 files, 493.90 GiB
baseline: C:\DOCUMENTS_2026-07-20\
bookkeeping projected for N = 36 retained snapshots

  target     chunks     unique   dedup        mean         p50         p95       index  manifest/snap    bookkeeping  overlap%
    256K    1198369     939824   1.238  432.17 KiB  345.20 KiB    1.00 MiB   43.02 MiB      72.50 MiB       2.59 GiB     80.95  <== recommended
    512K     598247     481315   1.206  865.69 KiB  692.90 KiB    2.00 MiB   22.03 MiB      54.19 MiB       1.93 GiB     80.00
      1M     304593     252674   1.169    1.66 MiB    1.34 MiB    4.00 MiB   11.57 MiB      45.22 MiB       1.60 GiB     78.97
      2M     155984     132368   1.136    3.24 MiB    2.63 MiB    8.00 MiB    6.06 MiB      40.69 MiB       1.44 GiB     77.51
      4M      80395      69525   1.107    6.29 MiB    5.17 MiB   16.00 MiB    3.18 MiB      38.38 MiB       1.35 GiB     75.34

recommended: 256K (lowest unique_bytes + projected bookkeeping; see --help for the heuristic — the choice stays with you)
note: overlap% measures real chunk overlap against the baseline tree — the honest proxy for cross-snapshot dedup.
```

## Derived figures (used in the 2026-07-11 design discussion)

Unique bytes ≈ dataset / dedup; churn ≈ (1 − overlap) × unique bytes
(over the baseline gap — **gap duration not recorded for this run**; the
`--baseline-age` flag, issue 00004, exists because of that omission):

| target | unique bytes | churn vs baseline |
|---|---|---|
| 256K | ~399 GiB | ~76 GiB |
| 1M   | ~423 GiB | ~89 GiB |
| 4M   | ~446 GiB | ~110 GiB |

- 256K vs 4M: +1.24 GiB bookkeeping buys ~47 GiB less unique storage and
  ~31 % smaller incrementals. Mean file size ≈ 1.9 MiB (277k files /
  494 GiB) — bytes-weighted file-size histogram pending (issue 00002).
- Store object count at 256K ≈ 940k files in objects/ (today's
  one-file-per-chunk layout); the R8 pack layer exists to make sub-256K
  viable (~4M+ objects otherwise).
- Sub-256K rows missing: default `--sizes` started at 256K (fixed by
  issue 00003). Decision blocked on rerunning with
  `--sizes 64K,128K,256K,512K,1M` + `--baseline-age` + extended analysis.
