# Does random padding hide a timing leak? A measurement

*Measurement only. No shipped ANC crate changed. Data, code and the exact commands are in [`randomized_padding_2026-10-29/`](randomized_padding_2026-10-29/). Host: one shared 4-vCPU virtual machine, so treat every number as "on this machine".*

## The short answer

**Randomizing the padding makes a leak much more expensive to find, if it is done right. It does not make a leak disappear, and done wrong it barely helps.**

1. With a fixed ceiling the pad already hides the real token-check leak (about 23 ns before padding) below what our tests can see: 6 ns in Spin, 1.5 ns in Hybrid, 300 ns in Sleep, at about 60,000 samples per class.
2. Adding fine-grained random delay raises the number of samples an attacker needs by a large factor. In Spin, a random extra of up to 20 percent of the ceiling (+31 µs on average) costs the attacker about 3,000 times more samples for a 23 ns leak; up to 100 percent (+152 µs) about 80,000 times more. Hybrid starts out quieter, so the same settings cost the attacker about 50,000 and 1.1 million times more.
3. It never reaches "impossible". A leak is found given enough samples, and a 1.2 µs leak was still found at 20 percent jitter with only 36,000 samples per class.
4. **My first design was wrong, and the data showed it.** With only 8 random steps, the noise itself had a shape an attacker could use, and a 0.3 µs leak was found at 100 percent jitter with 60,000 samples per class. Going to 256 steps removed that. Both experiments are recorded here.
5. If the random draw can be predicted, the protection is gone. The random number has to come from an unpredictable source.

## The question

You asked whether the padding time could be randomized so that a leak "gets lost in the noise". The idea makes sense: noise makes averages harder to compare. What we did not know was how much it helps, what it costs, and whether it hides the leak or only slows the attacker down.

## The method, in plain words

An attacker times many requests of two kinds (for example, a token that is wrong at the first byte, and one wrong at the last byte) and asks "do the two kinds take different times?". The crate's own test is a statistic called t. Its line is 4.5: above it, the two kinds are called distinguishable.

We built three ways of waiting, from the shipped pad itself (no crate code changed):

* **fixed:** the shipped pad at a 300 µs ceiling.
* **replace:** the release time is the ceiling plus a random extra. The random total replaces the fixed one.
* **add:** the fixed pad, then a second wait of a random length appended.

We ran each in the three wait modes (Sleep, Spin, Hybrid), at random extras of up to 5, 20 and 100 percent of the ceiling. Each combination ran in 5 separate process launches ("blocks") at about 12,000 samples per class per block, with the two kinds of request shuffled together so they share the same machine noise. The process was pinned to one CPU. About 7.6 million timings were kept in this main run.

### The controls (this is what makes it evidence)

A test that finds nothing proves nothing unless it can find something. So every run mixed six kinds of request:

| Kind | What it is | What we expect |
|---|---|---|
| A | The token check, wrong at byte 0 | The baseline |
| A2 | Exactly the same as A | **Negative control.** No difference exists, so the test should stay quiet |
| B | The token check, wrong at byte 31 | The real leak. The pad should hide it |
| D1 | A, plus a known 200 ns delay after release | **Positive control.** A real small leak |
| D2 | A, plus a known 1 µs delay | A real medium leak |
| D3 | A, plus a known 50 µs delay | A real big leak |

The delays are added after the pad releases, so the pad cannot hide them. Measured against the quietest runs, they came out as 322 ns, 1,156 ns and 51.6 µs (the spin loop and the clock add a little).

**Negative control result:** A against A2 never went above |Z| 2.2 in 21 settings (2.9 in the second experiment), and the crate's own test flagged 0 of 105 blocks (0 of 30). So the test does not cry wolf on this machine.

**Positive control result:** the 50 µs leak was found in all 21 settings. The 1.2 µs leak was found in every Spin and Hybrid setting and in 5 of 7 Sleep settings. The 0.3 µs leak was found in every Spin and Hybrid setting and in no Sleep setting. So the experiment can see small leaks in Spin and Hybrid, and Sleep is too noisy to see anything under about 0.3 µs even with a fixed ceiling.

The random draw was checked to be independent of the kind of request: no setting had a p-value below 0.03 (21 settings, so one this low is expected by chance).

## Results

**Terms.** "Noise sd" is the typical spread of response times in microseconds. "Smallest leak the crate test sees" is the smallest average difference that would reach the 4.5 line at the number of samples we collected. "Draw known" means we subtracted the random number back out, as an attacker who could predict it would.

### Experiment A: 8 random steps (my first design)

Condensed from [`randomized_padding_2026-10-29/tables.md`](randomized_padding_2026-10-29/tables.md). Rows show the "replace" policy; "add" is within noise of it in Spin and Hybrid.

| Mode | Jitter | Added mean (µs) | Noise sd (µs) | Smallest leak seen (ns) | 1.2 µs leak seen? | 0.3 µs leak seen? |
|---|---|---|---|---|---|---|
| Spin | fixed | 0 | 0.49 | 6.3 | yes (433) | yes (104) |
| Spin | 5% | 8.6 | 5.7 | 84 | yes (36) | yes (8.2) |
| Spin | 20% | 36 | 22 | 324 | yes (17) | yes (7.4) |
| Spin | 100% | 171 | 112 | 1,569 | yes (18) | **yes (7.4)** |
| Hybrid | fixed | 0 | 0.42 | 1.5 | yes (681) | yes (318) |
| Hybrid | 100% | 176 | 111 | 1,600 | yes (16) | yes (8.1) |
| Sleep | fixed | 0 | 18.5 | 297 | yes (12) | no (2.7) |
| Sleep | 100% | 177 | 115 | 1,729 | no (3.1) | no (1.3) |

(Numbers in brackets are the test statistic; 4.5 is the line.)

**What went wrong.** At 100 percent jitter in Spin the "smallest leak seen" is 1,569 ns, yet a 322 ns leak was still found. If the attacker only compared averages, a 322 ns leak would need about 5 million samples per class at this noise. The crate's other tests, which compare the shape of the timing distribution after cutting off the slow tail, found it with 60,000. The reason is in the data: the random extra took only 8 equally likely values, spaced 37 µs apart at 100 percent, while the machine's own noise is under 1 µs. The 8 clusters had sharp edges, and a small shift pushes some samples across an edge. Making the jitter wider did not help against that kind of test (the samples needed stayed near 20,000 from 5 to 100 percent).

| Policy (Spin) | Samples per class to see a 0.3 µs leak: averages only | Same: shape-aware test (measured) |
|---|---|---|
| fixed | 1.2 million | 113 |
| 5% | 1.1 million | 18,000 |
| 20% | 2.2 million | 22,000 |
| 100% | 5.0 million | 22,000 |

So the main run's design costs the shape-aware attacker a fixed 160 to 200 times and does not improve with width. That is a poor deal.

### Experiment B: 256 random steps, uniform or smooth

Same code with `STACK_JITTER_LEVELS=256` (steps now closer than the machine's own noise), Spin and Hybrid, 3 blocks, about 36,000 samples per class. "Smooth" means the extra is the average of four random draws (a bell shape with no sharp edge) instead of one flat draw.

**Spin**

| Policy | Jitter | Added mean (µs) | Noise sd (µs) | Smallest leak seen (ns) | 1.2 µs leak seen? | 0.3 µs leak seen? | Samples per class for 1.2 µs | for 0.3 µs | for 23 ns | Draw known: 1.2 µs test stat |
|---|---|---|---|---|---|---|---|---|---|---|
| fixed | 0% | 0 | 0.42 | 7.4 | yes (354) | yes (80) | about 2 | 19 | 3,700 | 354 |
| uniform | 20% | 31 | 22.6 | 420 | yes (8.4) | no (3.4) | 4,800 | 61,000 | 12 million | 330 |
| uniform | 100% | 152 | 111 | 2,075 | **no (1.1)** | no (1.5) | 116,000 | 1.5 million | 290 million | 314 |
| smooth | 20% | 31 | 9.3 | 246 | yes (15) | no (3.3) | 1,600 | 21,000 | 4.1 million | 347 |
| smooth | 100% | 152 | 45 | 1,221 | no (2.4) | no (0.8) | 40,000 | 515,000 | 100 million | 314 |

**Hybrid** (not shown line by line; the leak sizes it can see are within about 10 percent of Spin's): 20 percent uniform needs 5,100 samples for a 1.2 µs leak and 13 million for a 23 ns leak; 100 percent needs 118,000 and 300 million. Hybrid's fixed ceiling is quieter, so the fixed-ceiling baseline is lower (258 samples for a 23 ns leak) and the multipliers are larger. Full tables are in [`supplementary_256_levels/tables.md`](randomized_padding_2026-10-29/supplementary_256_levels/tables.md).

How to read it. With fine steps the cost grows with the noise, as the theory says. A leak of 1.2 µs, which a fixed ceiling shows in a single digit of samples, needs thousands of samples at +31 µs and over a hundred thousand at +152 µs. The "samples" columns are my estimates from the measured noise, scaled by the square root of the sample count. That scaling was checked: the smallest-detectable leak measured from the first two blocks, compared with all blocks, matched the prediction (median ratio 1.00, range 0.70 to 1.08 in experiment A; 0.96 to 1.04 in B).

### Other findings

* **Replace versus add.** In Spin and Hybrid they protect the same. In Sleep, "add" is expensive: even a 5 percent random extra adds about 100 µs on average, because the second wait is a real operating-system sleep that wakes late. Replace costs 10 µs at 5 percent.
* **Sleep mode is already noisy** (18 µs of spread with a fixed ceiling), so small random extras do almost nothing there (the attacker needs 1.2 to 4.5 times more samples at 5 to 20 percent).
* **Uniform versus smooth.** For the same added latency, the flat draw protects more, because it spreads the response times further (111 µs against 45 µs at +152 µs). The bell shape protects less per microsecond. Neither beats a fixed ceiling that is already quiet.
* **A predictable draw defeats it.** With the random number subtracted, the leak comes back at close to the fixed-ceiling strength (for example Spin, uniform 100 percent: test statistic 314 against 354 for the fixed ceiling). The experiment used a plain seeded generator, which is **not** safe for this. A real system needs an unpredictable source.

## What this proves, and what it does not

**Measured here:**
* The fixed ceiling hides the token check's timing difference to within 6 ns (Spin), 2 ns (Hybrid), 300 ns (Sleep) at about 60,000 samples per class. The real leak was never detected: the largest of 105 block-level tests was 2.5 (3.2 over 30 in experiment B) against a line of 4.5.
* The controls work: the experiment finds known leaks and stays quiet on a non-leak.
* Eight random steps leak through the shape of the noise. With 256 steps the same leak is no longer found at 100 percent jitter at the sample size that found it before.

**Inferred, not measured:**
* The sample counts for small leaks (23 ns, 0.3 µs) beyond what we collected. They come from scaling the measured noise.

**Not shown:**
* "No detection" is not "no leak". It means no leak larger than the smallest-leak column at that sample size.
* Only a leak that shifts the average (a constant extra delay) was tested. A leak that changes only the spread, or only the slow tail, was not.
* One machine: a shared virtual machine, which adds noise from other jobs. The host load stayed at or below 1.12 during the runs, which is essentially the experiment's own pinned thread.
* The random delay was built from many ready-made pads. A real version inside the pad would be a code change, and its overhead is untested.
* The per-sample timings are not committed (about 60 MB); the per-launch statistics are.

## The cost

Mean added latency is about half the jitter width. With the 300 µs ceiling used here: +31 µs for 20 percent (about 10 percent more), +152 µs for 100 percent (about 50 percent more). The slow tail grows too (p99 up by 47 µs and 267 µs).

## Recommendation

**Ship it as an opt-in option later, not now, and not as the default.** The ceiling is what hides the leak; the randomization is extra cost for an attacker, not a substitute. If you want it:

1. Draw from an unpredictable source (not a seeded generator), with fine steps (or a continuous draw). Eight steps is worse than useless.
2. Prefer "replace" to "add", especially in Sleep mode.
3. Start at about 20 percent of the ceiling. In Spin that is about +10 percent mean latency for roughly a 3,000-fold rise in the samples an attacker needs for a 23 ns leak (about 50,000-fold in Hybrid).
4. Do not use it in Sleep mode below 100 percent; it adds little.

Before shipping I would collect two more things: a version built inside the pad rather than from prebuilt pads, and runs on a quieter or different machine. The decision on whether the cost is worth it is yours.

## What it says about the Spin lead

The earlier reading that Spin padding sat just under the line (4.42) is **not reproduced** here: in 8 Spin blocks of the real token pair with a fixed ceiling, the crate's own test never went above 2.54, and the combined result was well under the line (|Z| 0.9 and 1.9). This experiment can see a difference of about 6 to 7 ns in Spin. That does not prove nothing is there below that, and it is a different measurement from the one that produced the 4.42, so the lead stays recorded, not closed. Randomizing would raise the cost of exploiting any such residual, but would not tell us whether one exists.
