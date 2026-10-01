## 6. Tractor Transmission

The Tractor Transmission changes operating mode only at zero requests in flight, so no request runs half on one configuration and half on another.

*New design: reference implementation compiled and tested on Rust 1.94*

### Metaphor and goal

An old tractor gearbox has no synchromesh, the part that lets a car change gear while moving. To change gear you stop, press the clutch, move the lever and let the clutch out. Shift while moving and the gears grind.

A governed service has operating modes: the policy version in force, the current signing key, the loaded configuration, enforcement on or off. Change one mid-request and a request can be checked under policy v7 but logged as v8. It can also be signed with one key and verified with another.

The goal is that a mode changes only while no request is running. Every request then reads exactly one mode from start to finish.

This is a new design. No STACK repository contains it today; of the seven components, only the Sentinel Hash-Chain in sentinel_os exists. The `stack-transmission` crate is its first implementation.

One name clash needs flagging. In sentinel_os, `queue_schema.py` calls its Redis job queue "the transmission" (`TransmissionQueue`). That queue moves jobs to workers and does not gate mode changes, and no code connects it to this crate.

Terms used below:

- **Gear.** One frozen configuration of the caller's own type, written `G`, plus its epoch.
- **Epoch.** The gear's sequence number. The first gear is 0, and each successful shift adds exactly 1.
- **Drive guard.** A token a request holds while it runs. While the token exists, the request counts as in flight.
- **RAII.** Resource Acquisition Is Initialization: cleanup code runs automatically when a value goes out of scope, even during a panic.
- **Clutch.** A flag that, while set, makes new requests wait instead of starting.
- **Mutex and condition variable.** A mutex lets one thread at a time touch shared state. A condition variable lets a thread sleep until another thread signals a change.
- **Unwind.** How Rust handles a panic: it walks back up the call stack and runs each value's cleanup code.
- **Poisoned lock.** Rust marks a mutex poisoned when a thread panics while holding it, as a warning that the state may be half-updated.

### Mechanism

**The protocol.** A worker calls `engage(timeout)` and gets a `DriveGuard`. The guard holds a shared pointer (`Arc`) to the gear engaged at that moment, so that gear cannot vanish mid-request. The guard also adds one to the in-flight count.

A controller calls `shift(new_config, timeout)`, which runs five steps:

1. Take ownership of the gearbox. A second shift gets RETRY `shift_in_progress` at once instead of queueing.
2. If the last shift rolled back, wait out a cooldown with the clutch up.
3. Press the clutch. New `engage()` calls park, each for up to its own timeout.
4. Wait for the in-flight count to reach zero.
5. Swap in the new gear with epoch old + 1, then release the clutch. Parked workers proceed on the new gear.

If step 4 does not finish before the timeout, the shift rolls back. The clutch comes up, the old gear stays, and the unused configuration comes back inside `ShiftRefused` for resubmission. A gear is never half-shifted.

The caller never picks the epoch, so epochs cannot be reused or skipped. A shift at epoch `u64::MAX` is refused by `checked_add` instead of wrapping to 0. In CNS terms (`/home/user/CNS/cns/gate.py`), `engage()` and `shift()` are ALPHA-position gates: preconditions checked before any work starts.

**Caps.** Every queue and wait has a ceiling in `TransmissionConfig` (src/config.rs). A zero cap, a zero wait or a wait above 24 hours fails construction, and no bad value is replaced by a default. The last two rows are fixed constants in the same file.

| Cap | Default | What it bounds |
|---|---|---|
| `max_in_flight` | 4096 | Drive guards out at once |
| `max_waiting_engagers` | 1024 | Callers parked on the clutch |
| `max_engage_wait` | 5 s | Longest timeout one `engage()` may ask for |
| `max_shift_timeout` | 30 s | Longest drain, so the longest admission pause per shift |
| `MAX_CONFIGURABLE_WAIT` | 24 h | Ceiling on both waits, so deadline arithmetic cannot overflow |
| `SHIFT_COOLDOWN_FACTOR` | 2 | Cooldown after a rollback, as a multiple of the time the clutch was held |

**The guard releases itself.** Dropping a guard lowers the count and wakes a waiting shifter, even while the worker is panicking (src/transmission.rs):

```rust
impl<G> Drop for DriveGuard<G> {
    fn drop(&mut self) {
        let panicking = std::thread::panicking();
        let mut st = self.inner.lock();
        match st.in_flight.checked_sub(1) {
            Some(n) => st.in_flight = n,
            None => {
                self.inner.halt_locked(&mut st, HaltCause::Invariant);
            }
        }
        telemetry::set_in_flight(st.in_flight);
        let wake_shifter = st.in_flight == 0 && st.clutch;
        drop(st);
        if wake_shifter {
            self.inner.drained.notify_all();
        }
        if panicking {
            telemetry::guard_panicked();
            tracing::warn!(
                epoch = self.gear.epoch(),
                "drive guard released during a panic; in-flight count decremented"
            );
        }
        // `self.gear` is dropped after this body returns, outside the lock.
    }
}
```

`checked_sub` makes a count that would go below zero halt the transmission instead of wrapping to a huge number. The public API cannot reach that path. It is a tripwire for a broken internal rule.

**The drain and the swap.** This is the core of `shift_inner` (src/transmission.rs). The halt check compares a halt generation number, explained in the red-team results under A4.

```rust
        // Press the clutch. From here until release, engage() parks.
        st.clutch = true;
        repair.clutch = true;
        telemetry::set_clutch(true);

        let drained = loop {
            if st.halted.is_some() || st.halt_gen != halt_gen {
                break Err(Reason::Halted);
            }
            if st.in_flight == 0 {
                break Ok(());
            }
            let Some(left) = remaining(deadline) else {
                break Err(Reason::DrainTimeout);
            };
            st = inner.wait(&inner.drained, st, left);
        };

        // Swap (or not) and release, all under the one lock acquisition, so
        // no engage() can observe the clutch up with the old gear after a
        // successful drain, or the new gear before it.
        let swapped = match drained {
            Ok(()) => {
                let old = std::mem::replace(&mut st.gear, Arc::new(Gear::new(to_epoch, new_config)));
                // Handed out of the lock; dropped by `shift_checked` after
                // the verdict is recorded (or by whoever still holds an Arc).
                retired = Some(old);
                telemetry::set_epoch(to_epoch);
                Ok(())
            }
            Err(reason) => {
                if reason == Reason::DrainTimeout {
                    let held = pressed_at.elapsed().min(inner.config.max_shift_timeout);
                    st.cooldown_until = Instant::now()
                        .checked_add(held.saturating_mul(SHIFT_COOLDOWN_FACTOR));
                }
                Err((reason, new_config))
            }
        };
        st.clutch = false;
        st.shifter = false;
        repair.clutch = false;
        repair.shifter = false;
        telemetry::set_clutch(false);
        let clutch_held = pressed_at.elapsed();
        drop(st);
        inner.released.notify_all();
```

The swap and the release happen under one hold of the lock. So no `engage()` can see the clutch up with the old gear after a good drain, or the new gear before it. The replaced gear is handed out and dropped only after the verdict is recorded.

**Repair on unwind.** Gauges are written while the lock is held, so a panicking metrics backend could interrupt a half-made change. Each such change is covered by an `UnwindRepair` scope guard, declared before the lock is taken (src/transmission.rs):

```rust
impl<G> Drop for UnwindRepair<'_, G> {
    fn drop(&mut self) {
        if !self.armed() {
            return;
        }
        // Reached only during an unwind that started while the lock was
        // held, so the mutex is poisoned. Take the state without clearing
        // the poison: the next caller recovers and halts as usual. No
        // telemetry here, so nothing can panic a second time.
        let mut st = match self.inner.state.lock() {
            Ok(st) => st,
            Err(poisoned) => poisoned.into_inner(),
        };
        if self.in_flight {
            st.in_flight = st.in_flight.saturating_sub(1);
        }
        if self.waiting {
            st.waiting_engagers = st.waiting_engagers.saturating_sub(1);
        }
        if self.clutch {
            st.clutch = false;
        }
        if self.shifter {
            st.shifter = false;
        }
        drop(st);
        self.inner.drained.notify_all();
        self.inner.released.notify_all();
    }
}
```

The repair emits no telemetry, so a broken backend cannot panic a second time and abort the process. The next caller finds the poison, clears it, counts it and halts the transmission. An operator then calls `operator_reset()`.

**Compare and swap.** `shift_from(expected_epoch, new_config, timeout)` shifts only if the engaged epoch still equals `expected_epoch`. Otherwise it refuses with RETRY `epoch_mismatch`, so racing controllers cannot silently overwrite each other. Plain `shift()` stays last-writer-wins, and its docs say so.

**What it guarantees, and what it does not.** Between a guard's creation and its drop, the engaged epoch does not change. Tests with real threads and a property test check this; there is no formal proof.

The gearbox does not check that a new configuration is valid: `G` is opaque, and the caller validates it first. It does not promise fairness to a worker parked through many back-to-back successful shifts.

**The tradeoff.** A shift pauses admission for the drain time, so long requests slow shifts down or make them roll back. The cheaper alternative lets old requests finish on the old gear while new ones start on the new gear. That puts two modes live at once, the exact condition this component exists to prevent.

**Python.** No Python implementation exists. The crate copies the CNS `GateOutcome` words rather than depending on the Python package.

### Failure mode and state resolution

Every refusal is a typed `Trip` that names the operation, the reason, the CNS outcome and the state resolution. No reason maps to PASS, and a unit test checks all 10 reasons. The kernel's quarantine resolution is never used, because the transmission has no sender or agent to isolate.

| Trip | Outcome | State resolution | Why |
|---|---|---|---|
| `engage_timeout_over_budget`: timeout above `max_engage_wait` | RETRY | Reject | The caller can resubmit with a smaller timeout. An over-budget timeout is never clamped and admitted. |
| `wait_queue_full`: clutch pressed and `max_waiting_engagers` already parked | RETRY | Reject | Caps how many threads one shift can leave blocked. Clears when the clutch comes up. |
| `clutch_wait_timeout`: clutch still pressed when the engage timeout ends | RETRY | Reject | A shift is draining. A retry after it finishes succeeds. |
| `in_flight_capacity`: `max_in_flight` guards out | RETRY | Reject, at once | A load cap that clears as guards drop. Returning at once avoids a second wait queue. |
| `shift_timeout_over_budget`: timeout above `max_shift_timeout` | RETRY | Reject | Bounds how long admission can pause. The clutch is never pressed, and the config is handed back. |
| `shift_in_progress`: another shift owns the gearbox | RETRY | Reject | One shift at a time. Refusing instead of queueing stops shifts piling up. |
| `epoch_mismatch`: `shift_from` named an epoch that is no longer engaged | RETRY | Reject | Another shift won, or this is a replay. Re-read the gear, rebuild, resubmit. |
| `drain_timeout`: in-flight work did not reach zero in time | RETRY | Rollback | The old gear and epoch stay, and parked workers proceed on them. A cooldown of twice the clutch time follows. |
| `epoch_exhausted`: engaged epoch is `u64::MAX` | TERMINAL_BREACH | Reject | No new epoch can be numbered without reuse. `engage()` keeps working on the current gear. |
| `halted`: operator halt, recovered poison or broken invariant | TERMINAL_BREACH | Halt | Resubmitting cannot fix it; only `operator_reset()` can. Guards already issued run to completion. |
| `halted` during a cooldown, drain or clutch wait | TERMINAL_BREACH | Halt; a pending shift is also rolled back | A halted component must not change mode. This holds even if the operator resets before the waiter wakes. |
| Lock poisoned by a panic under the lock | TERMINAL_BREACH on that call and every later one | Halt, cause `poisoned` | `UnwindRepair` already restored the state. Halting stops admission on state nobody has checked. |
| Worker panics while holding a guard | No verdict; only that request fails | None needed | The RAII drop lowers the count during the unwind and wakes a waiting shifter. |
| In-flight count would go below zero | Later calls get TERMINAL_BREACH | Halt, cause `invariant` | The drain guarantee can no longer be trusted. Unreachable through the public API. |
| Invalid `TransmissionConfig` | Construction error | Reject: nothing is built | A zero cap or out-of-range wait is never replaced by a default. |

**What can still panic.** The crate's own code never panics, and `shift()` contains a panic from dropping the replaced gear. Two panics from outside the crate can still reach a caller.

The first comes from a metrics or tracing backend that panics under the lock. The state is repaired during the unwind, and the next call halts.

The second is the caller's `G::drop` when a guard drops the last copy of an old gear. That panic is not contained, so `G::drop` must not panic. Both are assumptions the deployment must uphold, not properties the crate enforces.

### Observability and telemetry

All names follow the kernel convention and live in src/telemetry.rs. Every label value comes from a closed enum. A label taken from caller data would let an attacker create unlimited time series, which is called a cardinality attack.

The gear configuration may hold key material, so it is never logged, printed or used as a label. The convention of logging input length and SHA-256 does not apply here. The transmission receives no raw input and never reads `G`.

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `tack_transmission_engage_total` | Counter | `outcome` (pass, retry, terminal_breach) | One per `engage()` call |
| `tack_transmission_shift_total` | Counter | `outcome` | One per `shift()` or `shift_from()` call |
| `tack_transmission_trips_total` | Counter | `operation`, `reason` (10 values), `outcome`, `resolution` | One per refused call |
| `tack_transmission_engage_wait_seconds` | Histogram | `outcome` | Wall time of one `engage()`, including any clutch wait |
| `tack_transmission_shift_drain_seconds` | Histogram | `outcome` | How long the clutch was pressed, from press to swap or rollback |
| `tack_transmission_in_flight` | Gauge | none | Drive guards out now |
| `tack_transmission_waiting_engagers` | Gauge | none | Callers parked on the clutch |
| `tack_transmission_clutch_pressed` | Gauge | none | 1 while a shift holds the clutch, else 0 |
| `tack_transmission_gear_epoch` | Gauge | none | Engaged epoch; exact only up to 2^53 |
| `tack_transmission_halted` | Gauge | none | 1 while halted, else 0 |
| `tack_transmission_halts_total` | Counter | `cause` (operator, poisoned, invariant) | Moves into the halted state; a repeat halt is not counted |
| `tack_transmission_operator_resets_total` | Counter | none | Resets that cleared a halt |
| `tack_transmission_guard_panics_total` | Counter | none | Guards dropped during a panic; the count was still lowered |
| `tack_transmission_lock_poison_recoveries_total` | Counter | none | Times the state lock was found poisoned and recovered |
| `tack_transmission_gear_drop_panics_total` | Counter | none | Panics from a replaced gear's `G::drop`, contained inside `shift()` |

Gauges are written while the state lock is held, so two racing threads cannot leave a stale value behind. `Transmission::new` only registers the gauges, by adding zero. So building a second instance never clears another instance's halt signal.

**Spans.** A span is a timed, named stretch of work that tracing tools draw as one bar.

- `stack.transmission.engage` at DEBUG, because it is on the hot path. Fields: `timeout_ms`, `epoch`, `outcome`, `reason`.
- `stack.transmission.shift` at INFO. Fields: `timeout_ms`, `from_epoch`, `to_epoch`, `clutch_held_ms`, `cooldown_wait_ms`, `outcome`, `reason`.
- `stack.transmission.operator_halt` and `stack.transmission.operator_reset` at INFO.

Log events carry only epochs, causes and reasons. ERROR marks each halt and each contained gear-drop panic. WARN marks a rollback, a guard released during a panic and an operator reset; INFO marks "gear shifted"; DEBUG marks the other refusals.

**Alert rules.** The crate ships these as the `PROMETHEUS_RULES` constant in src/telemetry.rs. A unit test checks that every metric they name is declared.

```yaml
groups:
  - name: stack-transmission
    rules:
      - alert: TackTransmissionHalted
        expr: max(tack_transmission_halted) == 1
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "Transmission halted; all engage and shift calls are refused until operator_reset."
      - alert: TackTransmissionLockPoisoned
        expr: increase(tack_transmission_lock_poison_recoveries_total[1h]) > 0
        labels: { severity: critical }
        annotations:
          summary: "A thread panicked while holding the transmission state lock. This points at a bug."
      - alert: TackTransmissionClutchStuck
        expr: max(tack_transmission_clutch_pressed) == 1
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "Clutch pressed longer than any allowed shift timeout; admission is paused."
      - alert: TackTransmissionShiftRolledBack
        expr: increase(tack_transmission_trips_total{operation="shift",reason="drain_timeout"}[15m]) > 0
        labels: { severity: warning }
        annotations:
          summary: "A mode change timed out draining and was rolled back; the old gear is still engaged."
      - alert: TackTransmissionEngageRetryRatio
        expr: sum(rate(tack_transmission_engage_total{outcome="retry"}[5m])) / clamp_min(sum(rate(tack_transmission_engage_total[5m])), 1e-9) > 0.05
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "More than 5% of engage calls are being told to retry (clutch waits or capacity)."
      - alert: TackTransmissionInFlightSaturated
        expr: increase(tack_transmission_trips_total{operation="engage",reason="in_flight_capacity"}[5m]) > 0
        labels: { severity: warning }
        annotations:
          summary: "max_in_flight reached; work is being refused."
      - alert: TackTransmissionGuardPanics
        expr: increase(tack_transmission_guard_panics_total[10m]) > 0
        labels: { severity: warning }
        annotations:
          summary: "A worker panicked while holding a drive guard. The count was released, but the worker failed."
      - alert: TackTransmissionGearDropPanics
        expr: increase(tack_transmission_gear_drop_panics_total[1h]) > 0
        labels: { severity: warning }
        annotations:
          summary: "A replaced configuration panicked in Drop during a shift. The shift completed; the configuration type has a bug."
```

**Timing side channels.** ANC, the kernel's Active Timing Cancellation, pads responses so their timing reveals nothing. This component leaves three channels for ANC to cover, and does not close them itself.

- **The clutch window is visible.** While a shift drains, `engage()` blocks. A timer can therefore tell that a mode change, such as a key rotation, is under way. Padding must cover `max_engage_wait`, or treat a RETRY as a response to pad.
- **Refusals are fast.** They reveal load and halt state to a timer, though not secrets.
- **Old-gear cleanup.** The last guard to drop an old gear pays its `G::drop`, a small delay on one request that follows a shift.

Configuration content does not affect `engage()` timing, and red-team attack A13 measured that.

### Red-team results

An independent red team wrote 14 attacks as tests in tests/redteam.rs, each asserting the safe behaviour. The first run gave 6 passed and 8 failed. None was a fail-open: every refusal was already RETRY or TERMINAL_BREACH, never PASS.

| Attack | Result | Fix or limitation |
|---|---|---|
| A1. Metrics backend panics just after the clutch is pressed | Broke (major). After poison recovery and reset the clutch stayed pressed, so every engage timed out. | Fixed. `UnwindRepair` lifts the clutch and releases gearbox ownership on unwind. |
| A2. Backend panics in `engage()` after the in-flight increment, before the guard exists | Broke (major). The count leaked by 1, so every later shift rolled back. | Fixed. The repair lowers the count on unwind. |
| A3. Backend panics while a caller parks on the clutch | Broke (major). A phantom parked caller stayed; with a cap of 1, every later wait got `wait_queue_full`. | Fixed. The repair lowers `waiting_engagers` on unwind. |
| A4. Operator halts during a drain, then resets at once | Broke (major). 19 of 20 shifts still swapped the gear the operator meant to stop. | Fixed. Each halt bumps a halt generation counter, and a waiter that sees it change gives up with `halted`. |
| A5. Building a second `Transmission` while the first is halted | Broke (major). `new()` set the halted gauge to 0, silencing the critical alert. | Fixed. `new()` only registers gauges. Limitation: two live instances still overwrite each other's gauges. |
| A6. A controller retries the shift at once after each `drain_timeout` while one guard is held | Partial (major). The clutch was up in only 0 to 4 of about 5,000 samples. | Fixed. After a rollback the next shift waits 2 times the clutch time. Five runs then showed the clutch up in 63 to 69 percent of samples. |
| A7. A stale or replayed shift prepared against an old epoch | Broke (minor). It was accepted and numbered as the newest epoch. | Fixed. `shift_from` refuses with RETRY `epoch_mismatch`. Plain `shift()` stays last-writer-wins. |
| A8. The caller's `G::drop` panics when `shift()` drops the old gear | Broke (minor). The panic escaped, and the shift was never counted. | Fixed in `shift()`: dropped after the verdict, contained and counted. Limitation: a guard dropping the last copy cannot contain it. |
| A9. `Duration::MAX`, budget plus 1 ns, zero, and 24 h waits with `usize::MAX` caps | Held | Over-budget calls get RETRY with the config handed back. No deadline overflowed. |
| A10. 50 more callers while the clutch is pressed and 2 are parked | Held | All 50 got `wait_queue_full` in under 500 ms in total. The parked count stayed at 2. |
| A11. A leaked guard (`mem::forget`) tries to let a shift through | Held | Every shift rolls back. Limitation: no operator action clears a leaked count, so a restart is needed. |
| A12. Label cardinality across every path | Held | Every metric name and label value came from the closed vocabularies. |
| A13. Engage timing with a 1-byte gear against a 32 MiB gear | Held | Medians of 1.583 µs and 1.572 µs at 2,001 samples each. No detectable size dependence at that sample count. |
| A14. Mixed gears under halt and reset churn with racing shifts | Held | Zero mixed-gear observations, and every count ended at 0. |

A rerun of A6 for this section showed the clutch up in 3,361 of 5,055 samples, with 0 clutch-wait timeouts. The cooldown caps the pause at about one third of the time, set by the factor of 2.

One red-team test was edited by the fixer, with the reason recorded. A7 expected plain `shift()` to refuse a stale config, which no implementation can tell apart from a fresh one. Only that stale submission changed to `shift_from`; the original assertion stayed, and stricter checks were added.

Known limitations that remain:

- **Double panic.** A telemetry backend that panics while a thread is already unwinding aborts the process. That is Rust's double-panic rule, and no crate code can catch it.
- **`G::drop` in a guard.** Containing it would need `unsafe` or an `unwrap`, and the workspace lints deny both. The docs say `G::drop` must not panic.
- **Shared gauges.** Two instances in one process overwrite each other's gauge values. A closed-enum instance label would fix that, and it is an open question.
- **Leaked guards.** A forgotten guard blocks every shift until the process restarts.
- **Fairness.** The cooldown applies only after a rollback. A worker parked through many back-to-back successful shifts can still time out.
- **No ledger binding yet.** Shifts are not recorded in the Sentinel ledger. That would need a canonical SHA-256 digest of `G`, which the crate does not require today.
- **Blocking API.** It uses `std::sync` only, so async callers must go through a blocking-task executor.

A property test checks single-threaded operation sequences against a simple model. It ran proptest's default of 256 generated cases, each 1 to 199 operations long.

A stress test runs 8 workers with 1,500 successful engages each, plus 2 racing shifters. A rerun printed "stress: 48739 operations, 36268 engage retries, 420 shifts".

`cargo clippy -p stack-transmission --all-targets -- -D warnings` finished with no warnings. The final run of `cargo test -p stack-transmission --all-targets` passed 45 tests in five binaries: unit, model, redteam, telemetry and threads, in that order.

```text
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.20s
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.38s
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.73s
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.60s
```
