<div align="center">
	<h2>a9drv</h2>
</div>

[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6.svg?style=flat-square)]()
[![Language](https://img.shields.io/badge/language-Rust-orange.svg?style=flat-square)]()
[![Status](https://img.shields.io/badge/status-bound%20libusbK%20on%20a%20real%20device-brightgreen.svg?style=flat-square)]()

### Binds the Apple A9 DFU node to a driver that can actually reset the port — and can undo it.

A scriptable replacement for clicking through Zadig. It binds `USB\VID_05AC&PID_1227` to an already-present libusbK driver-store package, **verifies the achieved driver service**, and can restore the previous binding.

---

### The failure this exists to prevent

checkm8 performs a **host-initiated USB bus reset** after every stage attempt. That reset is not housekeeping — it is the trigger that runs the overwritten bootrom callback. On Windows the reset is performed by the bound kernel driver, and libusb only asks for it when that driver is libusbK or libusb0:

> *"the best we can do is cycle the pipes (and even then, the control pipe can not be reset using WinUSB)"*

Get it wrong and the failure is silent: the exploit reports *"Device did not enter pwned DFU Mode"*, which accuses the exploit. The exploit is fine. **The driver is wrong.** `a9drv` makes that step explicit, verifiable, and reversible.

---

### What does this do?

```
$ a9drv plan      # what would change, and why
$ a9drv apply     # bind the node to libusbK
$ a9drv verify    # read back the achieved service and say whether reset is real
$ a9drv restore   # put the previous binding back
```

`classify` reads the bound driver, `apply` performs the binding with elevation, `state`/`store` track the before/after so `restore` is possible, and `json` emits machine-readable output.

---

### Status

The **proven artefact** (`artefacts/a9drv-proven.exe`) is the binary that actually bound the DFU node to libusbK on real hardware — MEASURED, hashed, and recorded in [`RECOVERY.md`](RECOVERY.md). The rebuilt binary from current source builds and tests green but **has never been run against a device**, and is not a drop-in replacement (different size and layout). `RECOVERY.md` states that distinction plainly rather than implying equivalence.
