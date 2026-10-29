## Tables (all blocks)

Realized size of the injected delays (inferred from all cells): D1_200ns = 322 ns, D2_1us = 1156 ns, D3_50us = 51592 ns

### spin

| policy | jitter | blocks | n per class | added mean (us) | added p99 (us) | robust sd (us) | MDE raw (ns) | MDE best crop (ns) | sample x (crop) | samples for 23 ns leak | neg ctl Z | natural A-B Z |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fixed | 0% | 3 | 35932 | 0.0 | 0.0 | 0.42 | 1835 | 7.4 | 1.0 | 3.74e+03 | 2.20 | 1.94 |
| replace | 20% | 3 | 36072 | 31.3 | 47.1 | 22.63 | 3196 | 420.4 | 3213.7 | 1.21e+07 | 1.45 | 1.41 |
| replace | 100% | 3 | 35950 | 151.5 | 267.1 | 111.27 | 3694 | 2075.1 | 78282.5 | 2.93e+08 | 2.87 | 2.20 |
| replace_smooth | 20% | 3 | 35977 | 30.9 | 38.2 | 9.31 | 2095 | 246.4 | 1104.1 | 4.13e+06 | 0.73 | 1.17 |
| replace_smooth | 100% | 3 | 35893 | 152.3 | 226.9 | 45.40 | 3187 | 1221.3 | 27115.8 | 1.01e+08 | 2.29 | 2.62 |

Positive controls (|Z| of the best crop; crate line 4.5; raw Z in brackets):

| policy | jitter | D1 200 ns | D2 1 us | D3 50 us | adjusted Z of D2 (draw known) |
|---|---|---|---|---|---|
| fixed | 0% | 80.3 [-1.1] | 353.5 [1.8] | 2437.7 [92.1] | 353.5 |
| replace | 20% | 3.4 [-1.3] | 8.4 [-0.6] | 373.7 [71.4] | 329.5 |
| replace | 100% | 1.5 [-0.9] | 1.1 [0.2] | 74.0 [55.9] | 313.7 |
| replace_smooth | 20% | 3.3 [-0.0] | 14.7 [2.8] | 731.1 [105.3] | 347.1 |
| replace_smooth | 100% | 0.8 [-2.1] | 2.4 [0.0] | 153.1 [73.9] | 314.5 |

Mean-based versus shape-aware attacker (|Z| at the achieved n; samples per class to reach 4.5):

| policy | jitter | control | mean-based Z (predicted) | shape-aware Z (best crop) | n mean-based | n shape-aware |
|---|---|---|---|---|---|---|
| fixed | 0% | D1_200ns | 0.84 | 80.3 | 1.02e+06 | 1.13e+02 |
| fixed | 0% | D2_1us | 3.17 | 353.5 | 7.23e+04 | 5.82e+00 |
| replace | 20% | D1_200ns | 0.49 | 3.4 | 3.09e+06 | not reached |
| replace | 20% | D2_1us | 1.75 | 8.4 | 2.37e+05 | 1.04e+04 |
| replace | 100% | D1_200ns | 0.38 | 1.5 | 5.00e+06 | not reached |
| replace | 100% | D2_1us | 1.43 | 1.1 | 3.55e+05 | not reached |
| replace_smooth | 20% | D1_200ns | 0.51 | 3.3 | 2.85e+06 | not reached |
| replace_smooth | 20% | D2_1us | 1.93 | 14.7 | 1.96e+05 | 3.37e+03 |
| replace_smooth | 100% | D1_200ns | 0.52 | 0.8 | 2.66e+06 | not reached |
| replace_smooth | 100% | D2_1us | 1.74 | 2.4 | 2.40e+05 | not reached |

### hybrid

| policy | jitter | blocks | n per class | added mean (us) | added p99 (us) | robust sd (us) | MDE raw (ns) | MDE best crop (ns) | sample x (crop) | samples for 23 ns leak | neg ctl Z | natural A-B Z |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fixed | 0% | 3 | 35844 | 0.0 | 0.0 | 0.41 | 1861 | 2.0 | 1.0 | 2.58e+02 | 1.21 | 2.02 |
| replace | 20% | 3 | 35944 | 35.6 | 90.5 | 22.98 | 3160 | 437.2 | 50198.2 | 1.30e+07 | 1.05 | 1.66 |
| replace | 100% | 3 | 35967 | 159.5 | 304.1 | 112.49 | 8265 | 2093.0 | 1150258.5 | 2.98e+08 | 1.05 | 1.15 |
| replace_smooth | 20% | 3 | 35851 | 33.9 | 76.1 | 9.65 | 2712 | 250.2 | 16432.7 | 4.24e+06 | 2.12 | 1.62 |
| replace_smooth | 100% | 3 | 36236 | 163.8 | 281.0 | 46.58 | 5585 | 1235.3 | 400717.6 | 1.05e+08 | 1.17 | 0.84 |

Positive controls (|Z| of the best crop; crate line 4.5; raw Z in brackets):

| policy | jitter | D1 200 ns | D2 1 us | D3 50 us | adjusted Z of D2 (draw known) |
|---|---|---|---|---|---|
| fixed | 0% | 285.8 [-0.3] | 515.7 [3.2] | 2247.9 [134.0] | 515.7 |
| replace | 20% | 1.6 [-0.9] | 7.9 [1.7] | 352.7 [72.9] | 248.5 |
| replace | 100% | 0.7 [1.5] | 2.3 [2.7] | 77.5 [42.2] | 185.1 |
| replace_smooth | 20% | 2.4 [0.2] | 13.0 [0.9] | 653.7 [43.7] | 274.2 |
| replace_smooth | 100% | 2.1 [-0.2] | 2.5 [-0.5] | 146.9 [42.1] | 191.6 |

Mean-based versus shape-aware attacker (|Z| at the achieved n; samples per class to reach 4.5):

| policy | jitter | control | mean-based Z (predicted) | shape-aware Z (best crop) | n mean-based | n shape-aware |
|---|---|---|---|---|---|---|
| fixed | 0% | D1_200ns | 0.72 | 285.8 | 1.42e+06 | 8.89e+00 |
| fixed | 0% | D2_1us | 3.36 | 515.7 | 6.44e+04 | 2.73e+00 |
| replace | 20% | D1_200ns | 0.47 | 1.6 | 3.32e+06 | not reached |
| replace | 20% | D2_1us | 0.82 | 7.9 | 1.10e+06 | 1.15e+04 |
| replace | 100% | D1_200ns | 0.24 | 0.7 | 1.29e+07 | not reached |
| replace | 100% | D2_1us | 1.09 | 2.3 | 6.16e+05 | not reached |
| replace_smooth | 20% | D1_200ns | 0.52 | 2.4 | 2.70e+06 | not reached |
| replace_smooth | 20% | D2_1us | 1.15 | 13.0 | 5.52e+05 | 4.32e+03 |
| replace_smooth | 100% | D1_200ns | 0.23 | 2.1 | 1.33e+07 | not reached |
| replace_smooth | 100% | D2_1us | 0.91 | 2.5 | 8.79e+05 | not reached |

### Negative control calibration (A against A2, every cell)

Cells: 10. Best-crop |Z| above 4.5: 0. Primary (p95 crop) above 4.5: 0. Raw above 4.5: 0. Crate leak flags in single blocks: 0 of 30. Largest best-crop |Z|: 2.87; median 1.33.

### sqrt(n) check

MDE from the first two blocks over MDE from all blocks, divided by the sqrt(n) prediction: median 1.00, range 0.96 to 1.04 over 10 cells.

Host load average (1 minute) before each cell: max 1.00, median 0.55.
