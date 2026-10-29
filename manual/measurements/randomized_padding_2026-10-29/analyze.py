#!/usr/bin/env python3
"""Combine the padding_jitter launches into the numbers used in the write-up.

Usage: analyze.py <runs_dir> <summary.json> [tables.md] [realized_from_summary.json]

Needs only numpy and the standard library. Reads every *.json launch file in
<runs_dir> (the mode and block come from inside each file), combines the
blocks of each (mode, policy, width) cell, and writes:

* summary.json  every number, per cell, combined over all blocks, plus the
                host load seen, and a check that the sqrt(n) rule predicts
                how the MDE shrinks from the first two blocks to all blocks;
* tables.md     the tables the write-up quotes.

Conventions. A pair is class A against class X. "diff" is mean(X) - mean(A),
so a positive diff means X was slower. The crate's t (and the Z built from
it) is (mean_A - mean_X) / se, so a leak by a slower X gives a NEGATIVE t.
Only |t| is compared with the 4.5 line. The 4.5 line is the crate's own.

Z (combined t over blocks) is the Stouffer sum of the per-block t's divided
by sqrt(blocks). The per-block t's come from the crate's cropped Welch tests.

MDE (minimum detectable effect) is 4.5 x the combined standard error: the
smallest mean difference that would reach the crate's line at the n achieved.
"samples needed" for a leak of size d is n x (MDE / d)^2, because t grows as
sqrt(n). That scaling is an inference, not a measurement; the predicted and
measured t of the positive controls are compared to check it.
"""
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

LINE = 4.5
CROPS = [0.5, 0.75, 0.9, 0.95, 0.99, 0.999]
PRIMARY_CROP = 3  # p95, fixed in advance of the full run
NATURAL_LEAK_NS = 23.0  # median gap of the leaky victim, from anc_ceiling.md
X_NAMES = ["A2", "B", "D1_200ns", "D2_1us", "D3_50us"]


def norm_sf2(z):
    """Two-sided normal tail probability."""
    return math.erfc(abs(z) / math.sqrt(2.0))


def gamma_q(a, x):
    """Regularized upper incomplete gamma Q(a, x)."""
    if x <= 0:
        return 1.0
    if x < a + 1.0:
        term = 1.0 / a
        total = term
        n = a
        for _ in range(500):
            n += 1.0
            term *= x / n
            total += term
            if abs(term) < abs(total) * 1e-14:
                break
        return max(0.0, 1.0 - total * math.exp(-x + a * math.log(x) - math.lgamma(a)))
    tiny = 1e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 500):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        d = tiny if abs(d) < tiny else d
        c = b + an / c
        c = tiny if abs(c) < tiny else c
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-14:
            break
    return min(1.0, h * math.exp(-x + a * math.log(x) - math.lgamma(a)))


def chi2_sf(x, k):
    return gamma_q(k / 2.0, x / 2.0)


def pct_lookup(pairs, q):
    for p, v in pairs:
        if abs(p - q) < 1e-9:
            return v
    return None


def load(runs_dir):
    cells = defaultdict(list)
    hosts = []
    for f in sorted(Path(runs_dir).glob("*.json")):
        if f.name == "summary.json":
            continue
        d = json.loads(f.read_text())
        hosts.append(
            {
                "file": f.name,
                "mode": d["mode"],
                "block": d["block"],
                "launch_seed": d["launch_seed"],
                "cpus_allowed": d.get("cpus_allowed"),
                "env_before": d.get("env_before"),
                "env_after": d.get("env_after"),
                "total_wall_seconds": d.get("total_wall_seconds"),
                "build": d.get("build"),
            }
        )
        for c in d["cells"]:
            c = dict(c)
            c["block"] = d["block"]
            c["ceiling_ns"] = d["ceiling_ns"]
            cells[(d["mode"], c["policy"], c["width_pct"])].append(c)
    return cells, hosts


def combine_pair(blocks, x):
    """Combine one pair (A vs x) over a list of cell-blocks."""
    ps = [next(p for p in c["pairs"] if p["x_class"] == x) for c in blocks]
    out = {"blocks": len(ps)}
    n_a = sum(p["n_a"] for p in ps)
    n_x = sum(p["n_x"] for p in ps)
    out["n_a"], out["n_x"] = n_a, n_x
    # Raw mean difference: inverse-variance fixed effect.
    d = np.array([p["diff_ns"] for p in ps], dtype=float)
    se = np.array([p["se_ns"] for p in ps], dtype=float)
    w = 1.0 / se**2
    diff = float(np.sum(w * d) / np.sum(w))
    se_c = float(1.0 / math.sqrt(np.sum(w)))
    q = float(np.sum(w * (d - diff) ** 2))
    out["raw"] = {
        "diff_ns": diff,
        "se_ns": se_c,
        "z": diff / se_c,
        "mde_ns": LINE * se_c,
        "heterogeneity_q": q,
        "heterogeneity_p": chi2_sf(q, max(1, len(ps) - 1)),
        "block_sd_of_diff_ns": float(np.std(d, ddof=1)) if len(ps) > 1 else None,
        "mean_block_se_ns": float(np.mean(se)),
    }
    # Permutation p-values, Fisher's method.
    pp = [max(p["perm_p"], 1e-12) for p in ps]
    fisher = -2.0 * sum(math.log(v) for v in pp)
    out["perm"] = {
        "block_p": pp,
        "fisher_chi2": fisher,
        "fisher_p": chi2_sf(fisher, 2 * len(pp)),
    }
    # Bootstrap: per-block 95% CIs that exclude zero.
    excl = 0
    for p in ps:
        lo, hi = p["boot_ci95_ns"]
        if lo is not None and (lo > 0 or hi < 0):
            excl += 1
    out["boot_ci95_blocks_excluding_zero"] = excl
    # The crate's own max |t| per block.
    out["crate_leak_blocks"] = sum(1 for p in ps if p["crate_leak"])
    out["crate_max_abs_t_per_block"] = [p["crate_max_abs_t"] for p in ps]
    # Cropped statistics: Z by Stouffer, and the cropped mean difference.
    crops = []
    for j in range(len(CROPS)):
        ts = [p["t_cropped"][j]["t"] for p in ps]
        if any(t is None for t in ts):
            crops.append(None)
            continue
        z = float(np.sum(ts) / math.sqrt(len(ts)))
        dj = np.array([p["t_cropped"][j]["diff_ns"] for p in ps], dtype=float)
        sj = np.array([p["t_cropped"][j]["se_ns"] for p in ps], dtype=float)
        wj = 1.0 / sj**2
        dif = float(np.sum(wj * dj) / np.sum(wj))
        sec = float(1.0 / math.sqrt(np.sum(wj)))
        crops.append(
            {
                "p": CROPS[j],
                "z": z,
                "diff_ns": dif,
                "se_ns": sec,
                "mde_ns": LINE * sec,
            }
        )
    out["crops"] = crops
    valid = [c for c in crops if c]
    out["best_crop_abs_z"] = max(abs(c["z"]) for c in valid) if valid else None
    out["best_crop_mde_ns"] = min(c["mde_ns"] for c in valid) if valid else None
    out["primary_crop"] = crops[PRIMARY_CROP]
    # Second-order t and the known-draw (adjusted) analysis.
    t2 = [p["t_second_order"] for p in ps if p["t_second_order"] is not None]
    out["second_order_z"] = float(np.sum(t2) / math.sqrt(len(t2))) if t2 else None
    ta = [p["adjusted"]["t"] for p in ps if p["adjusted"]["t"] is not None]
    out["adjusted_raw_z"] = float(np.sum(ta) / math.sqrt(len(ta))) if ta else None
    adj = []
    for j in range(len(CROPS)):
        tj = [p["adjusted"]["t_cropped"][j]["t"] for p in ps]
        if any(t is None for t in tj):
            continue
        adj.append(abs(float(np.sum(tj) / math.sqrt(len(tj)))))
    out["adjusted_best_crop_abs_z"] = max(adj) if adj else None
    ks = [p["ks_p"] for p in ps if p["ks_p"] is not None]
    out["ks_p_min"] = min(ks) if ks else None
    return out


def summarize_cell(key, blocks):
    mode, policy, width = key
    out = {"mode": mode, "policy": policy, "width_pct": width, "blocks": len(blocks)}
    out["cpu_util_min"] = min(c["thread_cpu_utilization"] for c in blocks)
    out["cpu_util_mean"] = float(np.mean([c["thread_cpu_utilization"] for c in blocks]))
    out["load1_max"] = max(c["load_before"]["load_avg"][0] for c in blocks if c["load_before"]["load_avg"])
    out["not_served"] = sum(c["not_served"] for c in blocks)
    out["n_kept"] = sum(c["n_kept"] for c in blocks)
    # Independence of the jitter draw from the class.
    tab = np.zeros_like(np.array(blocks[0]["level_class_counts"], dtype=float))
    for c in blocks:
        tab += np.array(c["level_class_counts"], dtype=float)
    # Drop levels with too few draws for a chi-square test (expected count per
    # cell below 5, as happens in the tails of the smooth draw).
    tab = tab[:, tab.sum(0) >= 30]
    exp = tab.sum(1, keepdims=True) * tab.sum(0, keepdims=True) / tab.sum()
    chi = float(np.sum((tab - exp) ** 2 / exp))
    dof = (tab.shape[0] - 1) * (tab.shape[1] - 1)
    out["independence"] = {"chi2": chi, "df": dof, "p": chi2_sf(chi, dof)}
    # Latency of the un-delayed classes: average the per-block percentiles.
    lat = {}
    for q in (0.25, 0.5, 0.75, 0.99, 0.999):
        lat[q] = float(np.mean([pct_lookup(c["latency_undelayed"]["percentiles_ns"], q) for c in blocks]))
    out["latency"] = {
        "mean_ns": float(np.mean([c["latency_undelayed"]["mean_ns"] for c in blocks])),
        "sd_ns": float(math.sqrt(np.mean([c["latency_undelayed"]["var"] for c in blocks]))),
        "p50_ns": lat[0.5],
        "p99_ns": lat[0.99],
        "p999_ns": lat[0.999],
        "robust_sd_ns": (lat[0.75] - lat[0.25]) / 1.349,
    }
    out["pairs"] = {x: combine_pair(blocks, x) for x in X_NAMES}
    return out


def add_derived(summ, realized_override=None):
    """Costs against the fixed cell of the same mode, noise multipliers, and
    the realized size of each injected delay. The realized delay is the
    precision-weighted raw diff over every cell, unless an earlier, larger
    run's estimate is passed in (a small run's estimate is too noisy)."""
    realized = {}
    for x in X_NAMES[2:]:
        num = den = 0.0
        for c in summ.values():
            r = c["pairs"][x]["raw"]
            w = 1.0 / r["se_ns"] ** 2
            num += w * r["diff_ns"]
            den += w
        realized[x] = num / den
    if realized_override:
        realized = dict(realized_override)
    for (mode, policy, width), c in summ.items():
        base = summ.get((mode, "fixed", 0))
        if base is not None:
            c["added_latency"] = {
                k: c["latency"][k] - base["latency"][k]
                for k in ("mean_ns", "p50_ns", "p99_ns", "p999_ns")
            }
            for crop_key, name in (("best_crop_mde_ns", "best_crop"),):
                pass
            b_mde = base["pairs"]["B"]["best_crop_mde_ns"]
            a2_mde = base["pairs"]["A2"]["best_crop_mde_ns"]
            ref = np.mean([b_mde, a2_mde])
            mine = np.mean([c["pairs"]["B"]["best_crop_mde_ns"], c["pairs"]["A2"]["best_crop_mde_ns"]])
            c["noise_multiplier_best_crop"] = float(mine / ref)
            c["sample_multiplier_best_crop"] = float((mine / ref) ** 2)
            ref_raw = np.mean([base["pairs"]["B"]["raw"]["mde_ns"], base["pairs"]["A2"]["raw"]["mde_ns"]])
            mine_raw = np.mean([c["pairs"]["B"]["raw"]["mde_ns"], c["pairs"]["A2"]["raw"]["mde_ns"]])
            c["sample_multiplier_raw"] = float((mine_raw / ref_raw) ** 2)
        # MDE of the attacker's mean-difference tests, pooled over the null
        # and natural pairs (same noise, no injected delay).
        mdes_crop = [c["pairs"][x]["best_crop_mde_ns"] for x in ("A2", "B")]
        mdes_raw = [c["pairs"][x]["raw"]["mde_ns"] for x in ("A2", "B")]
        c["mde_best_crop_ns"] = float(np.mean(mdes_crop))
        c["mde_raw_ns"] = float(np.mean(mdes_raw))
        n_per_class = c["pairs"]["A2"]["n_a"]
        c["n_per_class"] = n_per_class
        c["samples_needed_for_natural_leak_best_crop"] = float(n_per_class * (c["mde_best_crop_ns"] / NATURAL_LEAK_NS) ** 2)
        c["samples_needed_for_natural_leak_raw"] = float(n_per_class * (c["mde_raw_ns"] / NATURAL_LEAK_NS) ** 2)
        c["samples_needed_for_realized"] = {
            x: float(n_per_class * (c["mde_best_crop_ns"] / realized[x]) ** 2) for x in X_NAMES[2:]
        }
        # Does the sqrt(n) scaling predict the measured raw z of the controls?
        pred = {}
        for x in X_NAMES[2:]:
            r = c["pairs"][x]["raw"]
            pred[x] = {
                "predicted_z": realized[x] / r["se_ns"],
                "measured_z": r["z"],
            }
        c["raw_z_prediction_check"] = pred
        # Mean-based attacker (compares averages) versus shape-aware attacker
        # (the crate's cropped tests): predicted |Z| from the mean shift and
        # the raw standard error, against the measured best-crop |Z|, and the
        # samples per class each would need to reach the 4.5 line, scaled by
        # sqrt(n) from n_per_class. The shape-aware figure is given only when
        # the line was actually reached (below it, the best-crop |Z| is
        # inflated by choosing the best of several crops).
        shape = {}
        for x in X_NAMES[2:]:
            r = c["pairs"][x]["raw"]
            zm = realized[x] / r["se_ns"]
            zb = c["pairs"][x]["best_crop_abs_z"]
            shape[x] = {
                "mean_based_z": zm,
                "best_crop_z": zb,
                "advantage": zb / zm if zm > 0 else None,
                "n_mean_based": n_per_class * (LINE / zm) ** 2,
                "n_shape_aware": n_per_class * (LINE / zb) ** 2 if zb >= LINE else None,
            }
        c["mean_vs_shape"] = shape
    return realized


def null_calibration(summ):
    z_best, z_raw, z_prim, leaks, nblocks = [], [], [], 0, 0
    for c in summ.values():
        p = c["pairs"]["A2"]
        z_best.append(p["best_crop_abs_z"])
        z_raw.append(abs(p["raw"]["z"]))
        z_prim.append(abs(p["primary_crop"]["z"]))
        leaks += p["crate_leak_blocks"]
        nblocks += p["blocks"]
    arr = lambda v: [float(x) for x in v]  # noqa: E731
    return {
        "cells": len(z_best),
        "cell_best_crop_abs_z": arr(sorted(z_best)),
        "cell_raw_abs_z": arr(sorted(z_raw)),
        "cell_primary_abs_z": arr(sorted(z_prim)),
        "cells_best_crop_above_line": int(sum(1 for z in z_best if z > LINE)),
        "cells_primary_above_line": int(sum(1 for z in z_prim if z > LINE)),
        "cells_raw_above_line": int(sum(1 for z in z_raw if z > LINE)),
        "crate_leak_flags_in_blocks": int(leaks),
        "blocks": int(nblocks),
    }


def md_tables(summ, realized, null, label):
    lines = [f"## Tables ({label})", ""]
    pol_rank = {"fixed": 0, "replace": 1, "replace_smooth": 2, "add": 3}
    keys = sorted({(k[1], k[2]) for k in summ}, key=lambda t: (pol_rank.get(t[0], 9), t[1]))
    order = keys
    modes = [m for m in ("sleep", "spin", "hybrid") if any(k[0] == m for k in summ)]
    lines.append(f"Realized size of the injected delays (inferred from all cells): "
                 + ", ".join(f"{k} = {v:.0f} ns" for k, v in realized.items()))
    lines.append("")
    for mode in modes:
        lines += [f"### {mode}", ""]
        lines.append(
            "| policy | jitter | blocks | n per class | added mean (us) | added p99 (us) | robust sd (us) | MDE raw (ns) | MDE best crop (ns) | sample x (crop) | samples for 23 ns leak | neg ctl Z | natural A-B Z |"
        )
        lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
        for pol, w in order:
            c = summ.get((mode, pol, w))
            if c is None:
                continue
            add = c.get("added_latency", {"mean_ns": 0.0, "p99_ns": 0.0})
            a2 = c["pairs"]["A2"]["best_crop_abs_z"]
            b = c["pairs"]["B"]["best_crop_abs_z"]
            lines.append(
                f"| {pol} | {w}% | {c['blocks']} | {c['n_per_class']} | {add['mean_ns']/1e3:.1f} | {add['p99_ns']/1e3:.1f} | "
                f"{c['latency']['robust_sd_ns']/1e3:.2f} | {c['mde_raw_ns']:.0f} | {c['mde_best_crop_ns']:.1f} | "
                f"{c.get('sample_multiplier_best_crop', 1.0):.1f} | {c['samples_needed_for_natural_leak_best_crop']:.2e} | {a2:.2f} | {b:.2f} |"
            )
        lines.append("")
        lines.append("Positive controls (|Z| of the best crop; crate line 4.5; raw Z in brackets):")
        lines.append("")
        lines.append("| policy | jitter | D1 200 ns | D2 1 us | D3 50 us | adjusted Z of D2 (draw known) |")
        lines.append("|---|---|---|---|---|---|")
        for pol, w in order:
            c = summ.get((mode, pol, w))
            if c is None:
                continue
            cells = []
            for x in ("D1_200ns", "D2_1us", "D3_50us"):
                p = c["pairs"][x]
                cells.append(f"{p['best_crop_abs_z']:.1f} [{p['raw']['z']:.1f}]")
            adj = c["pairs"]["D2_1us"]["adjusted_best_crop_abs_z"]
            lines.append(f"| {pol} | {w}% | " + " | ".join(cells) + f" | {adj:.1f} |")
        lines.append("")
        lines.append("Mean-based versus shape-aware attacker (|Z| at the achieved n; samples per class to reach 4.5):")
        lines.append("")
        lines.append("| policy | jitter | control | mean-based Z (predicted) | shape-aware Z (best crop) | n mean-based | n shape-aware |")
        lines.append("|---|---|---|---|---|---|---|")
        for pol, w in order:
            c = summ.get((mode, pol, w))
            if c is None:
                continue
            for x in ("D1_200ns", "D2_1us"):
                m = c["mean_vs_shape"][x]
                ns = f"{m['n_shape_aware']:.2e}" if m["n_shape_aware"] is not None else "not reached"
                lines.append(
                    f"| {pol} | {w}% | {x} | {m['mean_based_z']:.2f} | {m['best_crop_z']:.1f} | {m['n_mean_based']:.2e} | {ns} |"
                )
        lines.append("")
    lines += [
        "### Negative control calibration (A against A2, every cell)",
        "",
        f"Cells: {null['cells']}. Best-crop |Z| above 4.5: {null['cells_best_crop_above_line']}. "
        f"Primary (p95 crop) above 4.5: {null['cells_primary_above_line']}. Raw above 4.5: {null['cells_raw_above_line']}. "
        f"Crate leak flags in single blocks: {null['crate_leak_flags_in_blocks']} of {null['blocks']}. "
        f"Largest best-crop |Z|: {max(null['cell_best_crop_abs_z']):.2f}; median {float(np.median(null['cell_best_crop_abs_z'])):.2f}.",
        "",
    ]
    return "\n".join(lines)


def scaling_check(cells):
    """Does MDE shrink like 1/sqrt(n)? Compare the first two blocks with all
    blocks, per cell. observed = mde_first2 / mde_all; predicted =
    sqrt(n_all / n_first2). A ratio of observed over predicted near 1
    supports the sqrt(n) rule used for 'samples needed'."""
    rows = []
    for key, blocks in cells.items():
        blocks = sorted(blocks, key=lambda b: b["block"])
        if len(blocks) < 3:
            continue
        full = summarize_cell(key, blocks)
        part = summarize_cell(key, blocks[:2])
        mde_full = np.mean([full["pairs"][x]["best_crop_mde_ns"] for x in ("A2", "B")])
        mde_part = np.mean([part["pairs"][x]["best_crop_mde_ns"] for x in ("A2", "B")])
        n_full = full["pairs"]["A2"]["n_a"]
        n_part = part["pairs"]["A2"]["n_a"]
        pred = math.sqrt(n_full / n_part)
        obs = mde_part / mde_full
        rows.append({"cell": "%s|%s|%s" % key, "observed": float(obs), "predicted": float(pred), "ratio": float(obs / pred)})
    ratios = [r["ratio"] for r in rows]
    return {
        "rows": rows,
        "median_ratio": float(np.median(ratios)) if ratios else None,
        "min_ratio": float(min(ratios)) if ratios else None,
        "max_ratio": float(max(ratios)) if ratios else None,
    }


def run(runs_dir, summary_path, tables_path, realized_from=None):
    cells, hosts = load(runs_dir)
    summ = {key: summarize_cell(key, sorted(b, key=lambda x: x["block"])) for key, b in cells.items()}
    override = json.loads(Path(realized_from).read_text())["realized_delay_ns"] if realized_from else None
    realized = add_derived(summ, override)
    null = null_calibration(summ)
    scaling = scaling_check(cells)
    load1 = [c["load_before"]["load_avg"][0] for blocks in cells.values() for c in blocks if c["load_before"]["load_avg"]]
    result = {
        "hosts": hosts,
        "host_load1_before_cells": {"max": max(load1), "median": float(np.median(load1)), "cells": len(load1)},
        "realized_delay_ns": realized,
        "null_calibration": null,
        "sqrt_n_scaling_check": scaling,
        "cells": {"%s|%s|%s" % k: v for k, v in summ.items()},
    }
    Path(summary_path).write_text(json.dumps(result, indent=1, default=float))
    if tables_path:
        text = md_tables(summ, realized, null, "all blocks")
        if scaling["median_ratio"] is not None:
            text += (
                "\n### sqrt(n) check\n\nMDE from the first two blocks over MDE from all blocks, divided by the sqrt(n) "
                f"prediction: median {scaling['median_ratio']:.2f}, range {scaling['min_ratio']:.2f} to {scaling['max_ratio']:.2f} "
                f"over {len(scaling['rows'])} cells.\n"
            )
        text += (
            f"\nHost load average (1 minute) before each cell: max {result['host_load1_before_cells']['max']:.2f}, "
            f"median {result['host_load1_before_cells']['median']:.2f}.\n"
        )
        Path(tables_path).write_text(text)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    run(
        sys.argv[1],
        sys.argv[2],
        sys.argv[3] if len(sys.argv) > 3 else None,
        sys.argv[4] if len(sys.argv) > 4 else None,
    )
