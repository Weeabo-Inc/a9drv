# `a9drv` — recovery path: how to rebuild this tool with confidence

**Written 2026-10-03 by `driver-engineer` (task-3), after the source was finished, built and tested.**
Applies to `E:\Reverseing\Arlo\a9drv`. `P:` is frozen; `D:` is off limits.

## 1. The two binaries, and which one touched the phone

| | Path | SHA-256 | Size | State |
|---|---|---|---|---|
| **Proven artefact** | `a9drv\artefacts\a9drv-proven.exe` | `C5FD0BAFA0D4A11DCD61314E9F507222CD31E0FF5697B12D49EE789FDEDA5B0C` | 529,408 | **This is the binary that bound the DFU node to libusbK.** MEASURED: mine, re-hashed. |
| Same file, original path | `a9drv\target\release\a9drv.exe` | identical | 529,408 | mtime `11:48:19` — untouched by this work. |
| **Rebuilt from current source** | `a9drv\target-verify\release\a9drv.exe` | `1556D3D3D76E06B1B3605F591EFEB5FEDF44ECE0BEB9CFA14E6025820DEC2E4E` | 585,728 | Builds and tests green. **Has never been run against any device.** |

The rebuilt binary is **not** a drop-in replacement for the proven one: it is a different size
because five files were rewritten after the proven build, and it has not been exercised on
hardware. Treat it as the recovery candidate, not as the working tool.

## 2. Rebuild recipe (never writes to `target\release`)

```powershell
cd E:\Reverseing\Arlo\a9drv
$env:CARGO_TARGET_DIR = 'E:\Reverseing\Arlo\a9drv\target-verify'   # mandatory
cargo build --release --offline
cargo test  --release --offline
```

MEASURED, final run, nothing edited afterwards:

* `cargo build --release --offline` → exit 0; one warning (`store::staged_copy` is never used, see §5).
* `cargo test --release --offline` → **89 passed; 0 failed; 0 ignored; 0 measured** (last green before
  this work was 87; the two additions are the regression tests in §4).
* The suite is **offline and device-free**: no test calls `enumerate`, `compatible_drivers`,
  `apply::*`, `pnputil` or anything that opens a USB handle. Verified by inspection of every
  test module, and by the run itself completing in 0.06 s.
* No network was needed; `windows-sys 0.59` resolved from the local cargo cache
  (`--offline` succeeded on the first attempt).

## 3. What is MEASURED vs what is only INSPECTED

* MEASURED: the artefact hash and size, both binaries' identities, the build and test results,
  the 12:01:44 edit that damaged `src\pnp.rs`, and the old `cbSize` defect
  (see `.session-recovery\EVIDENCE.md` for the reproductions).
* INSPECTED: the fix-(a) call path — that `prepare()` now unions published INFs with the Windows
  compatible-driver list. Its *live* consequence depends on SetupAPI data for the device, which
  this task was forbidden to query.
* NOT MEASURED, therefore not claimed: that the rebuilt binary would achieve the same libusbK
  binding as the proven one. Nobody has run it against the phone.

## 4. The two real selection bugs — fixed, with pinning tests

Diagnosis per HANDOFF §3: **not** the `[Strings]` matcher (that was always correct), but these.

**(a) Candidates came only from `SetupDiBuildDriverInfoList(SPDIT_COMPATDRIVER)` — so libusbK was
never a candidate at all.**

* Old code, recovered verbatim from the authoring session log: `prepare()` had a single line,
  `let candidates = match pnp::compatible_drivers(&node.instance_id) {`.
* Fix — the selection source is now the published INFs on disk, with the Windows list kept only
  for reporting:
  * `store.rs:346` `scan_published` and `store.rs:350` `scan_published_in` — read `%SystemRoot%\INF\oemNN.inf`.
  * `store.rs:435` `as_candidate` — a published INF becomes a `CandidateSource::PublishedInf`.
  * `main.rs:910` `store::scan_published(&marker)`, `main.rs:917` the candidate list built from it,
    `main.rs:918-925` the union with the Windows list (`compat`), which `main.rs:898` still fetches
    so the report can say whether the chosen package is in it.
* Pinning test: `store.rs:623` `published_infs_are_a_selection_source_without_the_compat_list` —
  builds an INF directory containing a libusbK-style `oem46.inf` (model line reached through
  `%DeviceID%`), Apple's `oem45.inf`, and an unrelated `oem99.inf`, with **no** Windows list
  involved, and asserts the libusbK package is found, ordered, parsed and turned into a
  `PublishedInf` candidate naming `oem46.inf`.

**(b) `SetupApiGetDriverInfoDetail` / `SetupDiGetDriverInfoDetailW` was called with a buffer whose
`cbSize` was never initialised — so the INF name came back empty.**

* Old code, recovered verbatim: `let mut buf = vec![0u8; 4096];` passed straight to the API.
  SetupAPI then returns `FALSE`, `candidate_of` returns early, and the package is reported with an
  empty INF name. That empty name is the leading colon: `plan.rs:185` renders a candidate as
  `format!("{}:{}", c.inf_file, c.provider)`, so it printed `:Apple, Inc.`.
* Fix — the initialisation lives in one place:
  * `pnp.rs:625-633` `detail_buffer`, with `pnp.rs:630` `(*p).cbSize = size_of::<SP_DRVINFO_DETAIL_DATA_W>() as u32;`
  * used at `pnp.rs:652` (first call) and `pnp.rs:667` (the `ERROR_INSUFFICIENT_BUFFER` retry).
* Pinning test: `pnp.rs:1000` `detail_buffer_always_carries_its_cb_size`. It asserts the first four
  bytes of every buffer `detail_buffer` returns equal `size_of::<SP_DRVINFO_DETAIL_DATA_W>()`
  (1584), and states the defect literally by also checking that a plain zeroed buffer reads back
  `cbSize == 0`.
* It **does fail on the old defect** — proved by reinstating the defect in a throwaway copy of the
  crate: `assertion left == right failed: detail_buffer(0) left cbSize uninitialised, left: 0,
  right: 1584`.

## 5. What is still NOT proven, and other loose ends

1. **Nothing in this build has touched the phone.** The proven artefact is the only `a9drv` binary
   known to bind libusbK. `bind`, `restore` and `verify` were not run; no elevation, no `pnputil`,
   no Zadig.
2. **`a9drv list` will not name `oem46.inf`.** With (b) fixed it now *names* a package where it used
   to print a blank — that is, `oem45.inf` instead of the empty name — but `cmd_list`
   (`main.rs:677`) prints only the Windows compatible-driver list. `oem46.inf` appears through
   `prepare()`: `a9drv bind --dry-run` prints it under `PACKAGES CLAIMING THIS NODE`, and
   `a9drv bind` selects from it. `list` also prints the driver-store section, where libusbK shows up
   as the FileRepository *folder* name, not as `oem46.inf`.
   Whether that Windows list really contains only Apple's package is a live property of this
   machine's SetupAPI data. It was already measured once (HANDOFF §3) and is consistent with the
   old `(:Apple, Inc.)` output, but it was **not** re-measured here, because re-measuring it means
   running an `a9drv` command against the device and `verify` was forbidden even though it is
   read-only. Follow-up if wanted: have `cmd_list` also print the published-INF candidates, so the
   one always-available command shows `oem46.inf` too.
3. **`store::staged_copy` is dead code** (`store.rs:409`), and the build says so. It was written to
   report whether a published INF has a staged copy in the store — provenance the redesign never
   wired up. Harmless, one warning, deliberately left alone rather than guessed at.
4. **The repaired line** in `pnp.rs:971` `only_plausible_device_ids_are_reported` is the assertion the
   12:01:44 edit deleted: `is_plausible_device_id("USB\\VID_05AC&PID_1227")` — the generic hardware-ID
   form that `bind --method update` actually sends. Evidence in `.session-recovery\EVIDENCE.md`.
5. Hygiene, pre-existing: the `mask_ecid` test in `src\pnp.rs` uses a full-length ECID-shaped fixture
   that matches the real device's trailing digits. It is already in the tree, not introduced here,
   and no such value appears in this document or in the task report. Worth masking before any of
   this source is published.
