## Tables (all blocks)

Realized size of the injected delays (inferred from all cells): D1_200ns = 322 ns, D2_1us = 1156 ns, D3_50us = 51592 ns

### sleep

| policy | jitter | blocks | n per class | added mean (us) | added p99 (us) | robust sd (us) | MDE raw (ns) | MDE best crop (ns) | sample x (crop) | samples for 23 ns leak | neg ctl Z | natural A-B Z |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fixed | 0% | 5 | 60066 | 0.0 | 0.0 | 18.50 | 2586 | 297.1 | 1.0 | 1.00e+07 | 1.02 | 1.08 |
| replace | 5% | 5 | 60036 | 9.7 | 14.5 | 19.29 | 3056 | 324.4 | 1.2 | 1.19e+07 | 2.01 | 1.02 |
| replace | 20% | 5 | 60333 | 37.0 | 39.9 | 27.82 | 5020 | 513.7 | 3.0 | 3.01e+07 | 1.43 | 0.73 |
| replace | 100% | 5 | 60150 | 177.0 | 265.2 | 114.86 | 4205 | 1728.7 | 33.9 | 3.40e+08 | 0.70 | 1.06 |
| add | 5% | 5 | 59541 | 100.3 | 140.8 | 25.17 | 3254 | 451.0 | 2.3 | 2.29e+07 | 0.86 | 0.37 |
| add | 20% | 5 | 59983 | 129.3 | 217.0 | 35.33 | 3336 | 631.4 | 4.5 | 4.52e+07 | 1.16 | 0.80 |
| add | 100% | 5 | 59794 | 275.0 | 415.3 | 118.89 | 4363 | 1837.6 | 38.3 | 3.82e+08 | 1.87 | 1.12 |

Positive controls (|Z| of the best crop; crate line 4.5; raw Z in brackets):

| policy | jitter | D1 200 ns | D2 1 us | D3 50 us | adjusted Z of D2 (draw known) |
|---|---|---|---|---|---|
| fixed | 0% | 2.7 [1.5] | 12.2 [2.3] | 464.9 [94.0] | 12.2 |
| replace | 5% | 2.5 [0.4] | 10.2 [1.1] | 428.9 [96.1] | 10.6 |
| replace | 20% | 2.5 [-0.8] | 6.4 [1.1] | 306.9 [36.8] | 10.4 |
| replace | 100% | 1.3 [0.4] | 3.1 [1.7] | 94.6 [55.5] | 9.9 |
| add | 5% | 2.4 [1.9] | 10.1 [2.3] | 332.6 [81.1] | 10.6 |
| add | 20% | 2.5 [0.9] | 6.4 [1.1] | 242.7 [62.0] | 7.4 |
| add | 100% | 2.2 [1.9] | 2.7 [1.2] | 88.8 [50.1] | 6.1 |

Mean-based versus shape-aware attacker (|Z| at the achieved n; samples per class to reach 4.5):

| policy | jitter | control | mean-based Z (predicted) | shape-aware Z (best crop) | n mean-based | n shape-aware |
|---|---|---|---|---|---|---|
| fixed | 0% | D1_200ns | 0.62 | 2.7 | 3.14e+06 | not reached |
| fixed | 0% | D2_1us | 2.08 | 12.2 | 2.80e+05 | 8.20e+03 |
| replace | 5% | D1_200ns | 0.54 | 2.5 | 4.15e+06 | not reached |
| replace | 5% | D2_1us | 2.26 | 10.2 | 2.39e+05 | 1.17e+04 |
| replace | 20% | D1_200ns | 0.37 | 2.5 | 9.00e+06 | not reached |
| replace | 20% | D2_1us | 1.00 | 6.4 | 1.23e+06 | 2.94e+04 |
| replace | 100% | D1_200ns | 0.36 | 1.3 | 9.26e+06 | not reached |
| replace | 100% | D2_1us | 1.28 | 3.1 | 7.39e+05 | not reached |
| add | 5% | D1_200ns | 0.44 | 2.4 | 6.34e+06 | not reached |
| add | 5% | D2_1us | 1.86 | 10.1 | 3.48e+05 | 1.18e+04 |
| add | 20% | D1_200ns | 0.43 | 2.5 | 6.59e+06 | not reached |
| add | 20% | D2_1us | 1.56 | 6.4 | 4.98e+05 | 2.99e+04 |
| add | 100% | D1_200ns | 0.28 | 2.2 | 1.58e+07 | not reached |
| add | 100% | D2_1us | 1.23 | 2.7 | 8.06e+05 | not reached |

### spin

| policy | jitter | blocks | n per class | added mean (us) | added p99 (us) | robust sd (us) | MDE raw (ns) | MDE best crop (ns) | sample x (crop) | samples for 23 ns leak | neg ctl Z | natural A-B Z |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fixed | 0% | 5 | 59595 | 0.0 | 0.0 | 0.49 | 1290 | 6.3 | 1.0 | 4.53e+03 | 1.98 | 0.90 |
| replace | 5% | 5 | 60205 | 8.6 | 5.5 | 5.68 | 1508 | 83.8 | 174.5 | 7.98e+05 | 1.61 | 1.54 |
| replace | 20% | 5 | 60063 | 36.0 | 46.0 | 22.31 | 2630 | 324.3 | 2616.0 | 1.19e+07 | 0.73 | 0.88 |
| replace | 100% | 5 | 60190 | 170.9 | 270.1 | 111.64 | 3043 | 1568.8 | 61219.1 | 2.80e+08 | 1.76 | 0.85 |
| add | 5% | 5 | 60337 | 9.8 | 17.9 | 5.85 | 1597 | 85.5 | 181.9 | 8.34e+05 | 1.03 | 1.08 |
| add | 20% | 5 | 59991 | 35.6 | 56.0 | 22.36 | 1691 | 330.2 | 2712.7 | 1.24e+07 | 0.49 | 1.53 |
| add | 100% | 5 | 60279 | 171.6 | 280.8 | 111.32 | 3292 | 1568.8 | 61216.2 | 2.80e+08 | 0.77 | 1.49 |

Positive controls (|Z| of the best crop; crate line 4.5; raw Z in brackets):

| policy | jitter | D1 200 ns | D2 1 us | D3 50 us | adjusted Z of D2 (draw known) |
|---|---|---|---|---|---|
| fixed | 0% | 103.5 [1.9] | 433.3 [4.2] | 2946.9 [153.7] | 433.3 |
| replace | 5% | 8.2 [0.5] | 35.9 [3.6] | 1682.9 [139.1] | 469.5 |
| replace | 20% | 7.4 [2.2] | 17.3 [4.5] | 484.6 [98.5] | 393.1 |
| replace | 100% | 7.4 [1.4] | 17.9 [3.3] | 100.1 [73.6] | 402.4 |
| add | 5% | 8.4 [0.3] | 39.0 [1.4] | 1515.1 [122.6] | 280.8 |
| add | 20% | 5.5 [1.8] | 12.8 [2.3] | 470.7 [135.6] | 284.5 |
| add | 100% | 7.0 [-0.4] | 18.9 [0.6] | 98.2 [73.4] | 288.9 |

Mean-based versus shape-aware attacker (|Z| at the achieved n; samples per class to reach 4.5):

| policy | jitter | control | mean-based Z (predicted) | shape-aware Z (best crop) | n mean-based | n shape-aware |
|---|---|---|---|---|---|---|
| fixed | 0% | D1_200ns | 1.02 | 103.5 | 1.16e+06 | 1.13e+02 |
| fixed | 0% | D2_1us | 3.87 | 433.3 | 8.06e+04 | 6.43e+00 |
| replace | 5% | D1_200ns | 1.03 | 8.2 | 1.15e+06 | 1.83e+04 |
| replace | 5% | D2_1us | 3.81 | 35.9 | 8.41e+04 | 9.44e+02 |
| replace | 20% | D1_200ns | 0.74 | 7.4 | 2.22e+06 | 2.22e+04 |
| replace | 20% | D2_1us | 2.82 | 17.3 | 1.53e+05 | 4.09e+03 |
| replace | 100% | D1_200ns | 0.49 | 7.4 | 4.97e+06 | 2.22e+04 |
| replace | 100% | D2_1us | 1.73 | 17.9 | 4.05e+05 | 3.80e+03 |
| add | 5% | D1_200ns | 0.90 | 8.4 | 1.52e+06 | 1.71e+04 |
| add | 5% | D2_1us | 3.38 | 39.0 | 1.07e+05 | 8.03e+02 |
| add | 20% | D1_200ns | 0.81 | 5.5 | 1.86e+06 | 4.08e+04 |
| add | 20% | D2_1us | 3.22 | 12.8 | 1.17e+05 | 7.39e+03 |
| add | 100% | D1_200ns | 0.48 | 7.0 | 5.26e+06 | 2.48e+04 |
| add | 100% | D2_1us | 1.58 | 18.9 | 4.87e+05 | 3.42e+03 |

### hybrid

| policy | jitter | blocks | n per class | added mean (us) | added p99 (us) | robust sd (us) | MDE raw (ns) | MDE best crop (ns) | sample x (crop) | samples for 23 ns leak | neg ctl Z | natural A-B Z |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fixed | 0% | 5 | 60050 | 0.0 | 0.0 | 0.42 | 1085 | 1.5 | 1.0 | 2.48e+02 | 2.17 | 1.20 |
| replace | 5% | 5 | 59907 | 9.2 | 17.6 | 5.63 | 1064 | 85.5 | 3346.2 | 8.28e+05 | 1.29 | 0.95 |
| replace | 20% | 5 | 59988 | 40.3 | 107.3 | 22.40 | 2971 | 338.8 | 52550.4 | 1.30e+07 | 0.63 | 0.80 |
| replace | 100% | 5 | 60297 | 175.9 | 316.8 | 111.26 | 3698 | 1599.6 | 1171277.0 | 2.92e+08 | 0.62 | 0.95 |
| add | 5% | 5 | 59590 | 10.3 | 23.8 | 5.66 | 1516 | 86.7 | 3439.2 | 8.46e+05 | 1.93 | 3.09 |
| add | 20% | 5 | 59744 | 35.7 | 60.8 | 22.26 | 1291 | 331.9 | 50419.6 | 1.24e+07 | 1.42 | 0.67 |
| add | 100% | 5 | 60028 | 171.4 | 286.7 | 113.63 | 2578 | 1575.7 | 1136526.1 | 2.82e+08 | 1.19 | 1.68 |

Positive controls (|Z| of the best crop; crate line 4.5; raw Z in brackets):

| policy | jitter | D1 200 ns | D2 1 us | D3 50 us | adjusted Z of D2 (draw known) |
|---|---|---|---|---|---|
| fixed | 0% | 317.6 [-1.4] | 680.9 [4.4] | 2958.0 [198.5] | 680.9 |
| replace | 5% | 8.5 [1.8] | 37.8 [6.3] | 1720.2 [198.4] | 580.8 |
| replace | 20% | 5.4 [1.2] | 13.5 [1.6] | 456.6 [69.7] | 284.1 |
| replace | 100% | 8.1 [1.0] | 16.4 [1.6] | 99.8 [56.7] | 269.5 |
| add | 5% | 7.1 [-0.3] | 36.5 [2.6] | 1589.1 [146.3] | 524.3 |
| add | 20% | 14.7 [3.1] | 15.8 [5.3] | 466.1 [195.2] | 516.5 |
| add | 100% | 10.5 [1.0] | 16.7 [2.9] | 98.4 [87.7] | 302.7 |

Mean-based versus shape-aware attacker (|Z| at the achieved n; samples per class to reach 4.5):

| policy | jitter | control | mean-based Z (predicted) | shape-aware Z (best crop) | n mean-based | n shape-aware |
|---|---|---|---|---|---|---|
| fixed | 0% | D1_200ns | 1.65 | 317.6 | 4.45e+05 | 1.21e+01 |
| fixed | 0% | D2_1us | 4.56 | 680.9 | 5.85e+04 | 2.62e+00 |
| replace | 5% | D1_200ns | 1.49 | 8.5 | 5.47e+05 | 1.69e+04 |
| replace | 5% | D2_1us | 5.14 | 37.8 | 4.59e+04 | 8.49e+02 |
| replace | 20% | D1_200ns | 0.45 | 5.4 | 6.10e+06 | 4.23e+04 |
| replace | 20% | D2_1us | 2.09 | 13.5 | 2.78e+05 | 6.70e+03 |
| replace | 100% | D1_200ns | 0.37 | 8.1 | 8.85e+06 | 1.85e+04 |
| replace | 100% | D2_1us | 1.39 | 16.4 | 6.31e+05 | 4.55e+03 |
| add | 5% | D1_200ns | 1.08 | 7.1 | 1.04e+06 | 2.42e+04 |
| add | 5% | D2_1us | 3.57 | 36.5 | 9.46e+04 | 9.04e+02 |
| add | 20% | D1_200ns | 1.18 | 14.7 | 8.73e+05 | 5.63e+03 |
| add | 20% | D2_1us | 4.85 | 15.8 | 5.15e+04 | 4.86e+03 |
| add | 100% | D1_200ns | 0.57 | 10.5 | 3.72e+06 | 1.11e+04 |
| add | 100% | D2_1us | 1.88 | 16.7 | 3.43e+05 | 4.38e+03 |

### Negative control calibration (A against A2, every cell)

Cells: 21. Best-crop |Z| above 4.5: 0. Primary (p95 crop) above 4.5: 0. Raw above 4.5: 0. Crate leak flags in single blocks: 0 of 105. Largest best-crop |Z|: 2.17; median 1.19.

### sqrt(n) check

MDE from the first two blocks over MDE from all blocks, divided by the sqrt(n) prediction: median 1.00, range 0.70 to 1.08 over 21 cells.

Host load average (1 minute) before each cell: max 1.12, median 0.47.
