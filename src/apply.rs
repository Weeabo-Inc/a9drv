//! The only module in a9drv that changes anything.
//!
//! Two ways to force a package onto the node, both of them documented Windows
//! driver-installation paths. Neither installs, copies, imports or deletes a
//! driver package; both select a package that is *already* in the driver store,
//! which is the entire reason this tool does not need to ship a driver.
//!
//! * [`Method::DriverStore`] - `SetupDiSetSelectedDriverW` +
//!   `DiInstallDevice` from `newdev.dll`. Scoped to **one device node** and
//!   driven by the compatible-driver list, so the package is named by its store
//!   identity (`oem46.inf`) and no path has to be guessed.
//! * [`Method::UpdateDriverForPnp`] - `UpdateDriverForPlugAndPlayDevicesW` with
//!   `INSTALLFLAG_FORCE`. The classic `devcon update` path: it takes an INF path
//!   and a hardware ID, and installs for **every present device** with that
//!   hardware ID. Kept because it is the more battle-tested of the two and the
//!   right fallback when the per-node path is refused.
//!
//! Both are reached only from `bind`/`restore`, only after the elevation gate,
//! and both are followed by a re-read of the bound service.

use std::path::{Path, PathBuf};

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    DiInstallDevice, SetupDiDestroyDriverInfoList, SetupDiSetSelectedDriverW,
    SPDIT_COMPATDRIVER,
};
use windows_sys::Win32::Foundation::{GetLastError, BOOL, HWND};

use crate::pnp::{self, Candidate};

/// WIN32 error codes worth a sentence. Anything else is reported by number only.
pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_NO_MORE_ITEMS: u32 = 259;
pub const ERROR_NOT_FOUND: u32 = 1168;
pub const ERROR_NO_SUCH_DEVINST: u32 = 0xE000_020B;

/// Which API to use to force the package onto the node.
///
/// # Why `UpdateDriverForPnp` is the default, on measurement
///
/// `DiInstallDevice` needs the package to be in the node's compatible-driver
/// list. Measured on this host: that list contains exactly one package for the
/// DFU node, Apple's `oem45.inf`, even though `oem46.inf`/`oem47.inf` are in the
/// store with a model line for `USB\VID_05AC&PID_1227`. The list is not a
/// reliable way to reach them.
///
/// `UpdateDriverForPlugAndPlayDevicesW` takes the INF **path** and a hardware ID,
/// so it does not depend on that list at all. That is the step Zadig performs; it
/// is the path this tool defaults to. `DiInstallDevice` stays available because it
/// is scoped to a single device node and is the better choice when the package
/// *is* in the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Method {
    /// Per-hardware-ID, explicit INF path, `INSTALLFLAG_FORCE`. Default.
    #[default]
    UpdateDriverForPnp,
    /// Per-node, driver-store identity.
    DriverStore,
}

impl Method {
    pub fn parse(s: &str) -> Option<Method> {
        match s.trim().to_ascii_lowercase().as_str() {
            "di" | "store" | "diinstalldevice" => Some(Method::DriverStore),
            "update" | "pnp" | "forced" => Some(Method::UpdateDriverForPnp),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Method::UpdateDriverForPnp => {
                "UpdateDriverForPlugAndPlayDevices (explicit INF path + hardware ID, INSTALLFLAG_FORCE)"
            }
            Method::DriverStore => "DiInstallDevice (one device node, from the compatible-driver list)",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Method::UpdateDriverForPnp => "update",
            Method::DriverStore => "di",
        }
    }

    pub fn other(&self) -> Method {
        match self {
            Method::DriverStore => Method::UpdateDriverForPnp,
            Method::UpdateDriverForPnp => Method::DriverStore,
        }
    }
}

/// What the driver API said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    pub ok: bool,
    pub win32: u32,
    pub method: Method,
    pub reboot_required: bool,
    /// Set when the call failed before reaching the API at all (for example the
    /// package was not in the compatible-driver list). Then `win32` is 0 and this
    /// explains it.
    pub early_error: Option<String>,
}

impl ApplyOutcome {
    fn failed(method: Method, win32: u32) -> ApplyOutcome {
        ApplyOutcome {
            ok: false,
            win32,
            method,
            reboot_required: false,
            early_error: None,
        }
    }

    pub fn explanation(&self) -> String {
        if let Some(e) = &self.early_error {
            return e.clone();
        }
        win32_explain(self.win32).to_string()
    }
}

/// Plain English for the Win32 codes that can actually come back from these two
/// calls. The raw number is always printed next to it: the sentence is help, the
/// number is evidence.
pub fn win32_explain(code: u32) -> &'static str {
    match code {
        ERROR_SUCCESS => {
            "the API returned failure but reported no error - re-read the bound service to see \
             what state the node is actually in"
        }
        ERROR_FILE_NOT_FOUND => "the INF file was not found at the path given",
        ERROR_ACCESS_DENIED => {
            "access denied - another process is holding the device node, or policy is blocking \
             the package"
        }
        ERROR_INVALID_PARAMETER => "the driver API rejected the hardware ID or the INF path",
        ERROR_NO_MORE_ITEMS => "no present device matched the hardware ID given",
        ERROR_NOT_FOUND => "the driver package is no longer in the driver store",
        ERROR_NO_SUCH_DEVINST => "the device node disappeared while it was being worked on",
        _ => "unrecognised Win32 error - the number is the evidence, the sentence is not available",
    }
}

/// The published name (`oem46.inf`) resolves to `%SystemRoot%\INF\oem46.inf`.
pub fn inf_path_for(inf_file: &str) -> PathBuf {
    crate::store::inf_directory().join(inf_file)
}

/// Accept a published name, a bare INF name, or a full path.
pub fn resolve_inf_path(name_or_path: &str) -> Option<PathBuf> {
    let p = Path::new(name_or_path);
    if p.is_absolute() {
        return p.exists().then(|| p.to_path_buf());
    }
    if name_or_path.contains(['\\', '/']) {
        return p.exists().then(|| p.to_path_buf());
    }
    let candidate = inf_path_for(name_or_path);
    if candidate.exists() {
        return Some(candidate);
    }
    // Last resort: the staged copy inside the driver store, matched by the INF's
    // own file name. This is the same package; it just has not been published
    // under an oemNN.inf name.
    resolve_in_staged_store(name_or_path)
}

fn resolve_in_staged_store(original_inf: &str) -> Option<PathBuf> {
    let packages = crate::store::scan().ok()?;
    let pkg = packages
        .iter()
        .find(|p| p.original_inf.eq_ignore_ascii_case(original_inf))?;
    let path = crate::store::store_inf_path(pkg);
    path.exists().then_some(path)
}

/// The INF path to force for a chosen package: an explicit path wins, then the
/// path recorded on the candidate, then the published location, then the store.
pub fn resolve_target_inf(
    inf_file: &str,
    explicit: Option<&str>,
    candidates: &[crate::pnp::Candidate],
) -> Option<PathBuf> {
    if let Some(e) = explicit {
        let p = Path::new(e);
        if p.is_absolute() || e.contains(['\\', '/']) {
            if p.exists() {
                return Some(p.to_path_buf());
            }
        }
    }
    if let Some(c) = candidates
        .iter()
        .find(|c| c.inf_file.eq_ignore_ascii_case(inf_file))
    {
        if let Some(p) = &c.path {
            if p.exists() {
                return Some(p.clone());
            }
        }
    }
    resolve_inf_path(inf_file)
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

/// Force a store package onto one device node, by its published name.
///
/// Returns `Err` only when the device or its driver list could not be opened -
/// which is a different failure class from "the install was refused" and is
/// reported as such by the caller.
pub fn install_from_store(instance_id: &str, inf_file: &str) -> Result<ApplyOutcome, String> {
    let mut dev = pnp::open_device(instance_id)?;
    pnp::build_driver_list(&mut dev)?;

    // Find the driver-list entry whose INF is the published name we chose.
    let mut found: Option<(Candidate, windows_sys::Win32::Devices::DeviceAndDriverInstallation::SP_DRVINFO_DATA_V2_W)> =
        None;
    let mut index: u32 = 0;
    while let Some(drv) = pnp::enum_driver(dev.set, &dev.di, index) {
        index += 1;
        let cand = pnp::candidate_of(dev.set, &dev.di, &drv);
        if cand.inf_file.eq_ignore_ascii_case(inf_file) {
            found = Some((cand, drv));
            break;
        }
    }

    let Some((cand, mut drv)) = found else {
        // SAFETY: built above.
        unsafe { SetupDiDestroyDriverInfoList(dev.set, &dev.di, SPDIT_COMPATDRIVER) };
        return Ok(ApplyOutcome {
            ok: false,
            win32: 0,
            method: Method::DriverStore,
            reboot_required: false,
            early_error: Some(format!(
                "{inf_file} is not in this node's compatible-driver list, so there is nothing to \
                 select (SetupAPI matches packages by hardware ID; if the package exists in the \
                 store but is not listed here, it does not claim this device)"
            )),
        });
    };
    let _ = &cand;

    // SAFETY: live set, live device element, and a driver-list entry from that
    // same list. Declares the choice; does not install.
    let selected = unsafe { SetupDiSetSelectedDriverW(dev.set, &mut dev.di, &mut drv) };
    if selected == 0 {
        let err = last_error();
        // SAFETY: built above.
        unsafe { SetupDiDestroyDriverInfoList(dev.set, &dev.di, SPDIT_COMPATDRIVER) };
        return Ok(ApplyOutcome {
            ok: false,
            win32: err,
            method: Method::DriverStore,
            reboot_required: false,
            early_error: Some(format!(
                "SetupDiSetSelectedDriverW refused {inf_file} for this node (GetLastError={err}: {})",
                win32_explain(err)
            )),
        });
    }

    let mut reboot: BOOL = 0;
    // SAFETY: the driver info data comes from the list built for this device,
    // which is the documented precondition for DiInstallDevice.
    let ok = unsafe {
        DiInstallDevice(
            std::ptr::null_mut::<std::ffi::c_void>() as HWND,
            dev.set,
            &dev.di,
            &drv,
            0,
            &mut reboot,
        )
    };
    let err = if ok == 0 { last_error() } else { 0 };
    // SAFETY: built above; destroying the list only frees SetupAPI's copy.
    unsafe { SetupDiDestroyDriverInfoList(dev.set, &dev.di, SPDIT_COMPATDRIVER) };

    Ok(ApplyOutcome {
        ok: ok != 0,
        win32: err,
        method: Method::DriverStore,
        reboot_required: reboot != 0,
        early_error: None,
    })
}

/// The hardware-ID-scoped path.
pub fn update_for_pnp(hwid: &str, inf_path: &Path) -> ApplyOutcome {
    let hwid_w: Vec<u16> = hwid.encode_utf16().chain(std::iter::once(0)).collect();
    let path_w: Vec<u16> = inf_path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut reboot: BOOL = 0;
    // SAFETY: both strings are NUL-terminated and outlive the call.
    let ok = unsafe {
        windows_sys::Win32::Devices::DeviceAndDriverInstallation::UpdateDriverForPlugAndPlayDevicesW(
            std::ptr::null_mut::<std::ffi::c_void>() as HWND,
            hwid_w.as_ptr(),
            path_w.as_ptr(),
            windows_sys::Win32::Devices::DeviceAndDriverInstallation::INSTALLFLAG_FORCE,
            &mut reboot,
        )
    };
    if ok == 0 {
        ApplyOutcome::failed(Method::UpdateDriverForPnp, last_error())
    } else {
        ApplyOutcome {
            ok: true,
            win32: 0,
            method: Method::UpdateDriverForPnp,
            reboot_required: reboot != 0,
            early_error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_parsing_and_names() {
        assert_eq!(Method::parse("di"), Some(Method::DriverStore));
        assert_eq!(Method::parse("DI"), Some(Method::DriverStore));
        assert_eq!(Method::parse("store"), Some(Method::DriverStore));
        assert_eq!(Method::parse("update"), Some(Method::UpdateDriverForPnp));
        assert_eq!(Method::parse("pnp"), Some(Method::UpdateDriverForPnp));
        assert_eq!(Method::parse("nonsense"), None);
        assert_eq!(Method::DriverStore.name(), "di");
        assert_eq!(Method::UpdateDriverForPnp.name(), "update");
        assert_eq!(Method::DriverStore.other(), Method::UpdateDriverForPnp);
        assert_eq!(Method::UpdateDriverForPnp.other(), Method::DriverStore);
        // The label names the API, so a report can be checked against MSDN.
        assert!(Method::DriverStore.label().contains("DiInstallDevice"));
        assert!(Method::UpdateDriverForPnp.label().contains("INSTALLFLAG_FORCE"));
    }

    #[test]
    fn win32_codes_get_sentences_not_dumps() {
        assert!(win32_explain(ERROR_ACCESS_DENIED).contains("access denied"));
        assert!(win32_explain(ERROR_ACCESS_DENIED).contains("another process"));
        assert!(win32_explain(ERROR_FILE_NOT_FOUND).contains("INF file"));
        assert!(win32_explain(ERROR_NO_MORE_ITEMS).contains("no present device"));
        assert!(win32_explain(ERROR_NOT_FOUND).contains("driver store"));
        assert!(win32_explain(ERROR_NO_SUCH_DEVINST).contains("disappeared"));
        assert!(win32_explain(ERROR_SUCCESS).contains("no error"));
        assert!(win32_explain(0xDEAD_BEEF).contains("unrecognised"));
        // None of them may be an empty string: a silent explanation is worse
        // than none.
        for code in [0u32, 2, 5, 87, 259, 1168, 0xE000_020B, 12345] {
            assert!(!win32_explain(code).is_empty(), "code {code}");
        }
    }

    #[test]
    fn outcome_explanation_prefers_the_early_error() {
        let o = ApplyOutcome {
            ok: false,
            win32: 0,
            method: Method::DriverStore,
            reboot_required: false,
            early_error: Some("not in the compatible-driver list".to_string()),
        };
        assert_eq!(o.explanation(), "not in the compatible-driver list");
        let plain = ApplyOutcome::failed(Method::UpdateDriverForPnp, ERROR_ACCESS_DENIED);
        assert_eq!(plain.explanation(), win32_explain(ERROR_ACCESS_DENIED));
        assert!(!plain.ok);
        assert_eq!(plain.win32, 5);
    }

    #[test]
    fn resolves_published_names_to_the_inf_directory() {
        // A name that certainly does not exist must resolve to nothing rather
        // than to a path that is then passed to the driver API.
        assert_eq!(resolve_inf_path("oem-definitely-not-here.inf"), None);
        // The published name maps under %SystemRoot%\INF.
        let p = inf_path_for("oem46.inf");
        assert!(p.to_string_lossy().to_lowercase().ends_with(r"\inf\oem46.inf"));
    }
}
