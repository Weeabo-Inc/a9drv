//! SetupAPI layer: enumerate device nodes, read their properties, and build the
//! list of driver-store packages that could be bound to one.
//!
//! # Read-only by construction
//!
//! Everything in the read half of this file opens *no* device handle, writes no
//! registry value, and calls no function that installs, restarts or removes
//! anything. `SetupDiBuildDriverInfoList(SPDIT_COMPATDRIVER)` is the same call
//! Device Manager makes to *display* the list of compatible drivers for a device
//! before the user picks one; it builds an in-memory list. The two functions that
//! do change the device tree live in `apply.rs` and are reachable only from
//! `bind`/`restore` after an elevation check.
//!
//! # Why the properties are read the way they are
//!
//! A device's *bound driver service* - the single value that decides whether
//! checkm8 can run - is in `SPDRP_SERVICE` on the node's registry key, and is
//! also exposed as `DEVPKEY_Device_Service`. Both are read and reported when they
//! disagree, because "which of the two am I looking at" is precisely the kind of
//! ambiguity this project keeps losing days to.
//!
//! `HDEVINFO` is `isize` in every `windows-sys` release, never a pointer.
//! Failure is `INVALID_HANDLE_VALUE` (-1), and some paths return 0. `is_null()`
//! cannot work on it; that mistake is already documented in this project twice.

use std::mem::size_of;

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_DevNode_Status, SetupDiBuildDriverInfoList, SetupDiCreateDeviceInfoList,
    SetupDiDestroyDeviceInfoList, SetupDiDestroyDriverInfoList, SetupDiEnumDeviceInfo,
    SetupDiEnumDriverInfoW, SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW,
    SetupDiGetDevicePropertyW, SetupDiGetDeviceRegistryPropertyW, SetupDiGetDriverInfoDetailW,
    SetupDiOpenDeviceInfoW, CR_NO_SUCH_DEVNODE, CR_SUCCESS, DIGCF_ALLCLASSES, DIGCF_PRESENT,
    DN_HAS_PROBLEM, HDEVINFO, SP_DEVINFO_DATA, SP_DRVINFO_DATA_V2_W, SP_DRVINFO_DETAIL_DATA_W,
    SPDRP_COMPATIBLEIDS, SPDRP_DEVICEDESC, SPDRP_DRIVER, SPDRP_HARDWAREID, SPDRP_SERVICE,
    SPDIT_COMPATDRIVER,
};
use windows_sys::Win32::Devices::Properties::{
    DEVPKEY_Device_Class, DEVPKEY_Device_DriverInfPath, DEVPKEY_Device_DriverProvider,
    DEVPKEY_Device_DriverVersion, DEVPKEY_Device_FriendlyName, DEVPKEY_Device_IsPresent,
    DEVPKEY_Device_LocationInfo, DEVPKEY_Device_Parent, DEVPKEY_Device_Service, DEVPROPKEY,
    DEVPROPTYPE, DEVPROP_TYPE_BOOLEAN, DEVPROP_TYPE_FILETIME, DEVPROP_TYPE_STRING,
    DEVPROP_TYPE_STRING_LIST, DEVPROP_TYPE_UINT32,
};
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, HWND,
};

use crate::classify::{ResetCapability, ServiceKind};

pub const APPLE_VID: u16 = 0x05AC;
/// Apple's DFU-mode product ID. SecureROM DFU for every A-series SoC.
pub const DFU_PID: u16 = 0x1227;

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

fn null_hwnd() -> HWND {
    std::ptr::null_mut()
}

/// NUL-terminated UTF-16.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Lossy UTF-16 -> String, stopping at the first NUL.
fn utf16_until_nul(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn utf16_multi(bytes: &[u8]) -> Vec<String> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect::<Vec<u16>>()
        .split(|u| *u == 0)
        .filter(|chunk| !chunk.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

/// One device node, as much of it as SetupAPI will tell us without opening it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Node {
    pub instance_id: String,
    pub device_desc: String,
    pub friendly_name: Option<String>,
    pub class_name: Option<String>,
    pub hardware_ids: Vec<String>,
    pub compatible_ids: Vec<String>,
    /// `DEVPKEY_Device_Service`.
    pub devprop_service: Option<String>,
    /// `SPDRP_SERVICE` - the value the PnP manager actually loads.
    pub reg_service: Option<String>,
    /// `DEVPKEY_Device_DriverInfPath`, e.g. `oem45.inf`.
    pub driver_inf: Option<String>,
    /// `SPDRP_DRIVER`: the `Driver` subkey name of the bound package.
    pub reg_driver: Option<String>,
    pub provider: Option<String>,
    pub driver_version: Option<String>,
    pub location: Option<String>,
    pub parent: Option<String>,
    pub problem: Option<u32>,
    pub present: bool,
    /// Cross-check of `present` from `DEVPKEY_Device_IsPresent`. `None` when the
    /// property could not be read.
    pub present_prop: Option<bool>,
    pub vid: u16,
    pub pid: u16,
    /// An interface node (`&MI_xx`), not the function device itself.
    pub is_interface: bool,
}

impl Node {
    /// The bound driver service: what libusb will find when it opens the device.
    ///
    /// `SPDRP_SERVICE` first because it is the value the service loader reads.
    pub fn bound_service(&self) -> Option<&str> {
        match (&self.reg_service, &self.devprop_service) {
            (Some(a), _) if !a.is_empty() => Some(a.as_str()),
            (_, Some(b)) if !b.is_empty() => Some(b.as_str()),
            (Some(a), _) => Some(a.as_str()),
            _ => None,
        }
    }

    pub fn service_kind(&self) -> ServiceKind {
        self.bound_service()
            .map(ServiceKind::parse)
            .unwrap_or(ServiceKind::None)
    }

    pub fn reset_capability(&self) -> ResetCapability {
        self.service_kind().reset_capability()
    }

    /// The INF file name of the bound package, preferring the property.
    pub fn bound_inf(&self) -> Option<&str> {
        match (&self.driver_inf, &self.reg_driver) {
            (Some(a), _) if !a.is_empty() => Some(a.as_str()),
            (_, Some(b)) if !b.is_empty() => Some(b.as_str()),
            _ => None,
        }
    }

    /// Do the two independent reads of the service disagree? Worth saying out
    /// loud when they do, because it means the node is mid-change.
    pub fn service_sources_disagree(&self) -> bool {
        match (&self.reg_service, &self.devprop_service) {
            (Some(a), Some(b)) => !a.eq_ignore_ascii_case(b),
            _ => false,
        }
    }

    pub fn is_dfu(&self) -> bool {
        self.vid == APPLE_VID && self.pid == DFU_PID
    }

    /// Apple's USB serial descriptor (the last path component of the instance
    /// ID) for DFU/recovery nodes. Carries CPID/BDID/ECID; readable with no
    /// driver cooperation, which is why identification survives a broken binding.
    pub fn apple_serial(&self) -> Option<&str> {
        self.instance_id.rsplit('\\').next().filter(|s| s.contains(':'))
    }

    /// The most specific hardware ID SetupAPI reported, e.g.
    /// `USB\VID_05AC&PID_1227&REV_0000`.
    pub fn hwid_specific(&self) -> Option<&str> {
        self.hardware_ids
            .iter()
            .find(|h| h.contains("&REV_"))
            .or_else(|| self.hardware_ids.first())
            .map(|s| s.as_str())
    }

    /// The same ID without the `&REV_xxxx` qualifier, e.g.
    /// `USB\VID_05AC&PID_1227`.
    ///
    /// This is what `UpdateDriverForPlugAndPlayDevices` is given by default: it
    /// is the form Microsoft's own `devcon update` documentation uses, and it is
    /// the form the INF's model line uses. The printer always states which ID it
    /// chose, and `--hwid` overrides it.
    pub fn hwid_generic(&self) -> Option<String> {
        let spec = self.hwid_specific()?;
        let kept: Vec<&str> = spec
            .split('&')
            .filter(|part| !part.to_ascii_uppercase().starts_with("REV_"))
            .collect();
        Some(kept.join("&"))
    }
}

/// Where a candidate package description came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CandidateSource {
    /// Read out of a published INF in `%SystemRoot%\INF`. This is the list a9drv
    /// selects from.
    #[default]
    PublishedInf,
    /// Windows' own compatible-driver list for the node
    /// (`SetupDiBuildDriverInfoList(SPDIT_COMPATDRIVER)`). Measured on this host
    /// to contain only Apple's package for the DFU node, even though two signed
    /// libusbK packages are in the store; reported for diagnosis, not relied on.
    CompatDriverList,
}

impl CandidateSource {
    pub fn name(&self) -> &'static str {
        match self {
            CandidateSource::PublishedInf => "published_inf",
            CandidateSource::CompatDriverList => "windows_compat_list",
        }
    }
}

/// A driver package that could be bound to this node.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Candidate {
    /// `oem46.inf` - the published name in the store.
    pub inf_file: String,
    /// The INF on disk, when a path is known. Needed by the forced-update path,
    /// which is given an INF path rather than a store identity.
    pub path: Option<std::path::PathBuf>,
    pub source: CandidateSource,
    pub section: String,
    pub description: String,
    pub mfg: String,
    pub provider: String,
    pub version: String,
    pub date: String,
    /// The hardware/compatible ID in the device's list that this INF matched.
    /// Best-effort: SetupAPI omits it for some driver entries.
    pub hardware_id: String,
}

impl Candidate {
    /// A synthetic candidate, for the decision-logic tests. Never used in a run.
    #[cfg(test)]
    pub fn synthetic(inf_file: &str, provider: &str, version: &str) -> Candidate {
        Candidate {
            inf_file: inf_file.to_string(),
            path: None,
            source: CandidateSource::PublishedInf,
            section: "Install".to_string(),
            description: "Apple Mobile Device (DFU Mode)".to_string(),
            mfg: provider.to_string(),
            provider: provider.to_string(),
            version: version.to_string(),
            date: String::new(),
            hardware_id: String::new(),
        }
    }
}

/// A device-information set with one opened device, freed on drop.
pub struct OpenedDevice {
    pub set: HDEVINFO,
    pub di: SP_DEVINFO_DATA,
}

impl Drop for OpenedDevice {
    fn drop(&mut self) {
        if self.set != -1isize && self.set != 0 {
            // SAFETY: `set` came from SetupDiCreateDeviceInfoList.
            unsafe { SetupDiDestroyDeviceInfoList(self.set) };
        }
    }
}

/// Open a device by instance ID in a fresh device-information set.
pub fn open_device(instance_id: &str) -> Result<OpenedDevice, String> {
    // SAFETY: standard SetupAPI construction; the set is owned by OpenedDevice.
    let set = unsafe { SetupDiCreateDeviceInfoList(std::ptr::null(), null_hwnd()) };
    if set == -1isize || set == 0 {
        return Err(format!(
            "SetupDiCreateDeviceInfoList failed (GetLastError={})",
            last_error()
        ));
    }
    let mut di: SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
    di.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
    let id = wide(instance_id);
    // SAFETY: live set, NUL-terminated string, correctly sized struct.
    let ok = unsafe { SetupDiOpenDeviceInfoW(set, id.as_ptr(), null_hwnd(), 0, &mut di) };
    if ok == 0 {
        let err = last_error();
        // SAFETY: the set is no longer needed on this path.
        unsafe { SetupDiDestroyDeviceInfoList(set) };
        return Err(format!(
            "SetupDiOpenDeviceInfoW({instance_id}) failed (GetLastError={err})"
        ));
    }
    Ok(OpenedDevice { set, di })
}

/// Enumerate device nodes.
///
/// `include_not_present` also returns nodes that Windows remembers but that are
/// not in the tree right now - "ghost" nodes. They matter: this host has a ghost
/// `USB\VID_05AC&PID_1227` node in class *libusbk devices* from a previous unit,
/// and a tool that lists it as a live DFU device, or binds it, would be wrong.
pub fn enumerate(vid_filter: Option<u16>, include_not_present: bool) -> Result<Vec<Node>, String> {
    let mut flags = DIGCF_ALLCLASSES;
    if !include_not_present {
        flags |= DIGCF_PRESENT;
    }
    // SAFETY: standard enumeration; the set is destroyed before returning.
    let set = unsafe { SetupDiGetClassDevsW(std::ptr::null(), std::ptr::null(), null_hwnd(), flags) };
    if set == -1isize || set == 0 {
        return Err(format!(
            "SetupDiGetClassDevsW failed (GetLastError={})",
            last_error()
        ));
    }

    let mut out = Vec::new();
    let mut index: u32 = 0;
    loop {
        let mut di: SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
        di.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
        // SAFETY: live set, correctly sized struct.
        let ok = unsafe { SetupDiEnumDeviceInfo(set, index, &mut di) };
        if ok == 0 {
            let err = last_error();
            if err == ERROR_NO_MORE_ITEMS {
                break;
            }
            // Keep going for anything else, but do not spin forever if the API
            // is misbehaving.
            index += 1;
            if index > 20_000 {
                break;
            }
            continue;
        }
        index += 1;

        let node = read_node(set, &di);
        if vid_filter.map(|v| v == node.vid).unwrap_or(true) {
            out.push(node);
        }
    }

    // SAFETY: `set` came from SetupDiGetClassDevsW and is no longer used.
    unsafe { SetupDiDestroyDeviceInfoList(set) };
    out.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));
    Ok(out)
}

fn read_node(set: HDEVINFO, di: &SP_DEVINFO_DATA) -> Node {
    let hardware_ids = reg_property_multi(set, di, SPDRP_HARDWAREID).unwrap_or_default();
    let compatible_ids = reg_property_multi(set, di, SPDRP_COMPATIBLEIDS).unwrap_or_default();
    let instance_id = instance_id_of(set, di).unwrap_or_default();
    let (vid, pid) = hardware_ids
        .first()
        .and_then(|h| parse_vid_pid(h))
        .or_else(|| parse_vid_pid(&instance_id))
        .unwrap_or((0, 0));

    let (present_from_status, problem) = devnode_status(di);
    let present_prop = devprop(set, di, &DEVPKEY_Device_IsPresent).and_then(|v| v.as_bool());

    Node {
        instance_id,
        device_desc: reg_property_multi(set, di, SPDRP_DEVICEDESC)
            .and_then(|v| v.into_iter().next())
            .unwrap_or_default(),
        friendly_name: devprop(set, di, &DEVPKEY_Device_FriendlyName).and_then(|v| v.as_string()),
        class_name: devprop(set, di, &DEVPKEY_Device_Class).and_then(|v| v.as_string()),
        compatible_ids,
        hardware_ids: hardware_ids.clone(),
        devprop_service: devprop(set, di, &DEVPKEY_Device_Service).and_then(|v| v.as_string()),
        reg_service: reg_property_multi(set, di, SPDRP_SERVICE)
            .and_then(|v| v.into_iter().next()),
        driver_inf: devprop(set, di, &DEVPKEY_Device_DriverInfPath).and_then(|v| v.as_string()),
        reg_driver: reg_property_multi(set, di, SPDRP_DRIVER).and_then(|v| v.into_iter().next()),
        provider: devprop(set, di, &DEVPKEY_Device_DriverProvider).and_then(|v| v.as_string()),
        driver_version: devprop(set, di, &DEVPKEY_Device_DriverVersion)
            .and_then(|v| v.as_string()),
        location: devprop(set, di, &DEVPKEY_Device_LocationInfo).and_then(|v| v.as_string()),
        parent: devprop(set, di, &DEVPKEY_Device_Parent).and_then(|v| v.as_string()),
        problem,
        present: present_from_status || present_prop.unwrap_or(false),
        present_prop,
        vid,
        pid,
        is_interface: hardware_ids
            .iter()
            .any(|h| h.to_ascii_uppercase().contains("&MI_")),
    }
}

/// `(present, problem_code)`. Present is taken from `CM_Get_DevNode_Status`,
/// which reports `CR_NO_SUCH_DEVNODE` for a node that is not in the tree.
fn devnode_status(di: &SP_DEVINFO_DATA) -> (bool, Option<u32>) {
    let mut status: u32 = 0;
    let mut problem: u32 = 0;
    // SAFETY: both out-params are live; DevInst came from SetupAPI.
    let cr = unsafe { CM_Get_DevNode_Status(&mut status, &mut problem, di.DevInst, 0) };
    if cr == CR_NO_SUCH_DEVNODE {
        return (false, None);
    }
    if cr != CR_SUCCESS {
        // Unknown status: treat as not present so nothing gets bound by accident.
        return (false, None);
    }
    let has_problem = (status & DN_HAS_PROBLEM) != 0;
    (true, if has_problem { Some(problem) } else { None })
}

fn instance_id_of(set: HDEVINFO, di: &SP_DEVINFO_DATA) -> Option<String> {
    let mut needed: u32 = 0;
    // SAFETY: size probe with a null buffer.
    unsafe { SetupDiGetDeviceInstanceIdW(set, di, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return None;
    }
    let mut buf = vec![0u16; needed as usize + 2];
    // SAFETY: correctly sized buffer for the reported requirement.
    let ok = unsafe {
        SetupDiGetDeviceInstanceIdW(set, di, buf.as_mut_ptr(), buf.len() as u32, &mut needed)
    };
    if ok == 0 {
        return None;
    }
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..end]))
}

/// Read a possibly-multi-string `SPDRP_*` registry property.
fn reg_property_multi(
    set: HDEVINFO,
    di: &SP_DEVINFO_DATA,
    prop: u32,
) -> Option<Vec<String>> {
    let mut ty: u32 = 0;
    let mut size: u32 = 0;
    // SAFETY: size probe with a null buffer.
    let ok = unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            set,
            di,
            prop,
            &mut ty,
            std::ptr::null_mut(),
            0,
            &mut size,
        )
    };
    if ok == 0 && last_error() != ERROR_INSUFFICIENT_BUFFER {
        return None;
    }
    if size == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; size as usize + 4];
    // SAFETY: buffer is at least `size` bytes, as reported by the API.
    let ok2 = unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            set,
            di,
            prop,
            &mut ty,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut size,
        )
    };
    if ok2 == 0 {
        return None;
    }
    let n = (size as usize).min(buf.len());
    Some(utf16_multi(&buf[..n]))
}

/// A decoded device property.
#[derive(Debug, Clone, PartialEq)]
pub enum PropValue {
    Str(String),
    StrList(Vec<String>),
    U32(u32),
    Bool(bool),
    FileTime(u64),
    Other(u32),
}

impl PropValue {
    pub fn as_string(&self) -> Option<String> {
        match self {
            PropValue::Str(s) => Some(s.clone()),
            PropValue::StrList(v) => v.first().cloned(),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            PropValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// Read a `DEVPKEY_*` device property.
pub fn devprop(set: HDEVINFO, di: &SP_DEVINFO_DATA, key: &DEVPROPKEY) -> Option<PropValue> {
    let mut ty: DEVPROPTYPE = 0;
    let mut needed: u32 = 0;
    // SAFETY: size probe with a null buffer.
    let ok = unsafe {
        SetupDiGetDevicePropertyW(set, di, key, &mut ty, std::ptr::null_mut(), 0, &mut needed, 0)
    };
    if ok == 0 && last_error() != ERROR_INSUFFICIENT_BUFFER {
        return None;
    }
    let mut buf = vec![0u8; (needed as usize).max(8)];
    // SAFETY: buffer is at least the reported size.
    let ok2 = unsafe {
        SetupDiGetDevicePropertyW(
            set,
            di,
            key,
            &mut ty,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut needed,
            0,
        )
    };
    if ok2 == 0 {
        return None;
    }
    let n = (needed as usize).min(buf.len());
    Some(decode_prop(ty, &buf[..n]))
}

fn decode_prop(ty: DEVPROPTYPE, bytes: &[u8]) -> PropValue {
    match ty {
        DEVPROP_TYPE_STRING => PropValue::Str(utf16_until_nul(bytes)),
        DEVPROP_TYPE_STRING_LIST => PropValue::StrList(utf16_multi(bytes)),
        DEVPROP_TYPE_UINT32 => PropValue::U32(
            bytes
                .get(..4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .unwrap_or(0),
        ),
        DEVPROP_TYPE_BOOLEAN => PropValue::Bool(bytes.first().map(|b| *b != 0).unwrap_or(false)),
        DEVPROP_TYPE_FILETIME => PropValue::FileTime(
            bytes
                .get(..8)
                .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
                .unwrap_or(0),
        ),
        other => PropValue::Other(other),
    }
}

/// Build the compatible-driver list for the opened device. The list stays valid
/// until the device set is destroyed.
pub fn build_driver_list(dev: &mut OpenedDevice) -> Result<(), String> {
    // SAFETY: live set and struct; SPDIT_COMPATDRIVER builds an in-memory list.
    let ok = unsafe { SetupDiBuildDriverInfoList(dev.set, &mut dev.di, SPDIT_COMPATDRIVER) };
    if ok == 0 {
        return Err(format!(
            "SetupDiBuildDriverInfoList(SPDIT_COMPATDRIVER) failed (GetLastError={})",
            last_error()
        ));
    }
    Ok(())
}

/// Every package in the driver store that matches this node.
///
/// This is the answer to "is there a package present at all", which is what
/// separates *no matching package in the driver store* from *package present but
/// binding refused*.
pub fn compatible_drivers(instance_id: &str) -> Result<Vec<Candidate>, String> {
    let mut dev = open_device(instance_id)?;
    build_driver_list(&mut dev)?;
    let mut out = Vec::new();
    let mut i: u32 = 0;
    loop {
        let Some(drv) = enum_driver(dev.set, &dev.di, i) else {
            break;
        };
        i += 1;
        out.push(candidate_of(dev.set, &dev.di, &drv));
    }
    // SAFETY: the list was built by SetupDiBuildDriverInfoList above.
    unsafe { SetupDiDestroyDriverInfoList(dev.set, &dev.di, SPDIT_COMPATDRIVER) };
    out.sort_by(|a, b| a.inf_file.cmp(&b.inf_file));
    out.dedup_by(|a, b| a.inf_file == b.inf_file);
    Ok(out)
}

/// One entry of the compatible-driver list. `cbSize` must be set by the caller.
pub fn enum_driver(set: HDEVINFO, di: &SP_DEVINFO_DATA, index: u32) -> Option<SP_DRVINFO_DATA_V2_W> {
    let mut drv: SP_DRVINFO_DATA_V2_W = unsafe { std::mem::zeroed() };
    drv.cbSize = size_of::<SP_DRVINFO_DATA_V2_W>() as u32;
    // SAFETY: live set and struct; returns 0 when the index runs off the end.
    let ok = unsafe { SetupDiEnumDriverInfoW(set, di, SPDIT_COMPATDRIVER, index, &mut drv) };
    if ok == 0 {
        None
    } else {
        Some(drv)
    }
}

/// A zeroed detail buffer with `cbSize` correctly set.
///
/// This exists as its own function because omitting it is a silent, total
/// failure, and it happened: without `cbSize`, `SetupDiGetDriverInfoDetailW`
/// returns FALSE, `candidate_of` returns what it had, and every compatible
/// package is then reported with an **empty INF file name**. The visible symptom
/// was a log line reading `1 compatible package(s) exist for this node
/// (:Apple, Inc.)` - a leading colon where `oem45.inf` should have been - while
/// the process still exited successfully. A wrong-but-successful report is the
/// worst kind, so the initialisation lives in one tested place.
pub fn detail_buffer(size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size.max(size_of::<SP_DRVINFO_DETAIL_DATA_W>() + 2)];
    // SAFETY: the buffer is at least the size of the struct.
    unsafe {
        let p = buf.as_mut_ptr() as *mut SP_DRVINFO_DETAIL_DATA_W;
        (*p).cbSize = size_of::<SP_DRVINFO_DETAIL_DATA_W>() as u32;
    }
    buf
}

/// Fill in a `Candidate` from a driver-list entry, including the INF file name
/// which is only available through the detail call.
pub fn candidate_of(
    set: HDEVINFO,
    di: &SP_DEVINFO_DATA,
    drv: &SP_DRVINFO_DATA_V2_W,
) -> Candidate {
    let mut out = Candidate {
        description: utf16_units(&drv.Description),
        mfg: utf16_units(&drv.MfgName),
        provider: utf16_units(&drv.ProviderName),
        version: format_driver_version(drv.DriverVersion),
        date: filetime_to_date(filetime_to_u64(drv.DriverDate)).unwrap_or_default(),
        source: CandidateSource::CompatDriverList,
        ..Default::default()
    };

    let mut buf = detail_buffer(4096);
    let mut needed: u32 = 0;
    // SAFETY: `buf` starts with an SP_DRVINFO_DETAIL_DATA_W whose cbSize is set
    // by `detail_buffer`; only that fixed part is read back.
    let ok = unsafe {
        SetupDiGetDriverInfoDetailW(
            set,
            di,
            drv,
            buf.as_mut_ptr() as *mut SP_DRVINFO_DETAIL_DATA_W,
            buf.len() as u32,
            &mut needed,
        )
    };
    let ok = if ok == 0 && last_error() == ERROR_INSUFFICIENT_BUFFER && needed > 0 {
        buf = detail_buffer(needed as usize + 64);
        // SAFETY: same call with a buffer the API asked for.
        unsafe {
            SetupDiGetDriverInfoDetailW(
                set,
                di,
                drv,
                buf.as_mut_ptr() as *mut SP_DRVINFO_DETAIL_DATA_W,
                buf.len() as u32,
                &mut needed,
            )
        }
    } else {
        ok
    };
    if ok == 0 {
        return out;
    }

    // SAFETY: the API wrote a struct with cbSize at the front of `buf`.
    let detail = unsafe { &*(buf.as_ptr() as *const SP_DRVINFO_DETAIL_DATA_W) };
    out.section = utf16_units(&detail.SectionName);
    let inf = utf16_units(&detail.InfFileName);
    // The detail call can return a full path; the store name is the last part.
    out.inf_file = inf
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&inf)
        .to_string();
    // HardwareID is a variable-length tail whose presence SetupAPI does not
    // document clearly. It is read from its real field offset (not from
    // `size_of`, which includes trailing alignment padding), and only accepted
    // when it parses as a device ID - a wrong hardware ID in the report would be
    // worse than no hardware ID.
    let tail_start = std::mem::offset_of!(SP_DRVINFO_DETAIL_DATA_W, HardwareID);
    if buf.len() > tail_start + 4 {
        let candidate = utf16_until_nul(&buf[tail_start..]);
        if is_plausible_device_id(&candidate) {
            out.hardware_id = candidate;
        }
    }
    out
}

fn is_plausible_device_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 512
        && s.is_ascii()
        && s.contains('\\')
        && s.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}

fn utf16_units(buf: &[u16]) -> String {
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Driver versions are four packed 16-bit fields, most significant first.
pub fn format_driver_version(v: u64) -> String {
    if v == 0 {
        return String::new();
    }
    format!(
        "{}.{}.{}.{}",
        (v >> 48) & 0xFFFF,
        (v >> 32) & 0xFFFF,
        (v >> 16) & 0xFFFF,
        v & 0xFFFF
    )
}

fn filetime_to_u64(ft: windows_sys::Win32::Foundation::FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
}

/// FILETIME (100ns ticks since 1601-01-01) to `YYYY-MM-DD`.
pub fn filetime_to_date(ft: u64) -> Option<String> {
    if ft == 0 {
        return None;
    }
    let days = (ft / 864_000_000_000) as i64;
    // 1601-01-01 -> 1970-01-01 is 134774 days.
    let unix_days = days - 134_774;
    let (y, m, d) = civil_from_days(unix_days);
    Some(format!("{y:04}-{m:02}-{d:02}"))
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to a calendar date.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `USB\VID_05AC&PID_1227&REV_0000` -> `(0x05AC, 0x1227)`.
pub fn parse_vid_pid(s: &str) -> Option<(u16, u16)> {
    let up = s.to_uppercase();
    let vid = up.find("VID_")?;
    let pid = up.find("PID_")?;
    let v = u16::from_str_radix(up.get(vid + 4..vid + 8)?, 16).ok()?;
    let p = u16::from_str_radix(up.get(pid + 4..pid + 8)?, 16).ok()?;
    Some((v, p))
}

/// Mask the ECID inside a device instance ID or serial descriptor.
///
/// The ECID is a device-unique identifier. a9lab's research-log guard refuses to
/// record one, and console output is exactly what ends up pasted into issues and
/// READMEs, so a9drv masks it everywhere it prints - human and JSON alike. Enough
/// of it survives to tell two units apart, none of it identifies one.
pub fn mask_ecid(s: &str) -> String {
    let upper = s.to_ascii_uppercase();
    let Some(pos) = upper.find("ECID:") else {
        return s.to_string();
    };
    let start = pos + "ECID:".len();
    let end = s[start..]
        .find(|c: char| !c.is_ascii_hexdigit())
        .map(|off| start + off)
        .unwrap_or(s.len());
    let value = &s[start..end];
    if value.len() <= 6 {
        return s.to_string();
    }
    let masked = format!("{}...{}", &value[..2], &value[value.len() - 4..]);
    format!("{}{}{}", &s[..start], masked, &s[end..])
}

/// Match an instance ID against a pattern that may contain `...` wildcards, so
/// the masked ID printed by `a9drv list` can be pasted straight into
/// `--instance`.
pub fn instance_matches(pattern: &str, id: &str) -> bool {
    let p = pattern.to_ascii_lowercase();
    let hay = id.to_ascii_lowercase();
    let mut cursor = 0usize;
    for part in p.split("...") {
        if part.is_empty() {
            continue;
        }
        match hay[cursor..].find(part) {
            Some(off) => cursor += off + part.len(),
            None => return false,
        }
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectError {
    NoneForPid { pid: u16 },
    NoSuchInstance { instance: String },
    Ambiguous { instances: Vec<String> },
}

/// Pick the one node a command is about to act on.
///
/// Refusing to guess when two nodes match is deliberate: binding the wrong
/// phone's DFU node is silent and wasteful, and the ECID in the instance ID is
/// the only way to tell them apart.
pub fn select_node<'a>(
    nodes: &'a [Node],
    pid: u16,
    instance: Option<&str>,
    require_present: bool,
) -> Result<&'a Node, SelectError> {
    let pool: Vec<&Node> = nodes.iter().filter(|n| n.present || !require_present).collect();
    if let Some(want) = instance {
        let matching: Vec<&Node> = pool
            .into_iter()
            .filter(|n| instance_matches(want, &n.instance_id))
            .collect();
        return match matching.len() {
            0 => Err(SelectError::NoSuchInstance {
                instance: want.to_string(),
            }),
            1 => Ok(matching[0]),
            _ => Err(SelectError::Ambiguous {
                instances: matching
                    .iter()
                    .map(|n| mask_ecid(&n.instance_id))
                    .collect(),
            }),
        };
    }
    let matching: Vec<&Node> = pool.into_iter().filter(|n| n.pid == pid).collect();
    match matching.len() {
        0 => Err(SelectError::NoneForPid { pid }),
        1 => Ok(matching[0]),
        _ => Err(SelectError::Ambiguous {
            instances: matching
                .iter()
                .map(|n| mask_ecid(&n.instance_id))
                .collect(),
        }),
    }
}

/// How many present nodes would be affected by a hardware-ID-scoped operation.
pub fn count_present_with_hwid(nodes: &[Node], hwid: &str) -> usize {
    let want = hwid.to_ascii_lowercase();
    nodes
        .iter()
        .filter(|n| n.present)
        .filter(|n| n.hardware_ids.iter().any(|h| h.to_ascii_lowercase() == want))
        .count()
}

/// Find a node by exact instance ID, else by unique present PID match.
pub fn find_node<'a>(nodes: &'a [Node], instance_id: &str, pid: u16) -> Option<&'a Node> {
    if let Some(n) = nodes
        .iter()
        .find(|n| n.instance_id.eq_ignore_ascii_case(instance_id))
    {
        return Some(n);
    }
    let matching: Vec<&Node> = nodes.iter().filter(|n| n.present && n.pid == pid).collect();
    if matching.len() == 1 {
        return Some(matching[0]);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(instance: &str, present: bool, pid: u16) -> Node {
        Node {
            instance_id: instance.to_string(),
            present,
            pid,
            vid: APPLE_VID,
            hardware_ids: vec![format!("USB\\VID_05AC&PID_{pid:04X}&REV_0000")],
            ..Default::default()
        }
    }

    #[test]
    fn parses_vid_pid_from_the_real_instance_shapes() {
        assert_eq!(
            parse_vid_pid("USB\\VID_05AC&PID_1227&REV_0000"),
            Some((0x05AC, 0x1227))
        );
        assert_eq!(
            parse_vid_pid("USB\\VID_05AC&PID_1227\\CPID:8003_CPRV:01"),
            Some((0x05AC, 0x1227))
        );
        assert_eq!(parse_vid_pid("PCI\\VEN_1002&DEV_1638"), None);
        assert_eq!(parse_vid_pid(""), None);
        assert_eq!(parse_vid_pid("VID_ZZZZ&PID_1227"), None);
    }

    #[test]
    fn strips_the_rev_qualifier_for_the_broadcast_id() {
        let n = Node {
            hardware_ids: vec![
                "USB\\VID_05AC&PID_1227&REV_0000".to_string(),
                "USB\\VID_05AC&PID_1227".to_string(),
            ],
            ..Default::default()
        };
        assert_eq!(n.hwid_specific(), Some("USB\\VID_05AC&PID_1227&REV_0000"));
        assert_eq!(n.hwid_generic().as_deref(), Some("USB\\VID_05AC&PID_1227"));
    }

    #[test]
    fn formats_packed_driver_versions() {
        // 3.1.0.0 as SetupAPI packs it for the libusbK package on this host.
        assert_eq!(format_driver_version(0x0003_0001_0000_0000), "3.1.0.0");
        // 538 = 0x21A, Apple's driver version on this host.
        assert_eq!(format_driver_version(0x021A_0000_0000_0000), "538.0.0.0");
        assert_eq!(format_driver_version(0), "");
    }

    #[test]
    fn converts_filetime_to_a_calendar_date() {
        // 1970-01-01 in FILETIME, and the day after.
        assert_eq!(
            filetime_to_date(116_444_736_000_000_000).as_deref(),
            Some("1970-01-01")
        );
        assert_eq!(
            filetime_to_date(116_444_736_000_000_000 + 86_400_000_0000).as_deref(),
            Some("1970-01-02")
        );
        assert_eq!(filetime_to_date(0), None);
        // Verified independently on this host:
        //   (Get-Date '2024-06-13 00:00:00Z').ToFileTimeUtc() = 133627104000000000
        // and 2024-06-13 is the DriverVer date of the libusbK package in the
        // driver store, so `a9drv list` on this machine must print 2024-06-13.
        assert_eq!(
            filetime_to_date(133_627_104_000_000_000).as_deref(),
            Some("2024-06-13")
        );
    }

    #[test]
    fn only_plausible_device_ids_are_reported() {
        // The generic form (no `&REV_`) is the one `hwid_generic()` hands to
        // `UpdateDriverForPlugAndPlayDevices`, so it has to survive the filter
        // as well as the specific one.
        assert!(is_plausible_device_id("USB\\VID_05AC&PID_1227"));
        assert!(is_plausible_device_id("USB\\VID_05AC&PID_1227&REV_0000"));
        assert!(!is_plausible_device_id(""));
        assert!(!is_plausible_device_id("garbage without a slash"));
        assert!(!is_plausible_device_id("\u{4e00}\u{672c}\u{8a9e}"));
    }

    /// The regression test for `detail_buffer`, and the reason that function
    /// exists at all.
    ///
    /// The defect it pins was real and silent, and it is fix (b) of the rebind
    /// that would not happen: `candidate_of` handed
    /// `SetupDiGetDriverInfoDetailW` a plain `vec![0u8; 4096]`, so the struct's
    /// `cbSize` was never written and stayed zero. The call then fails with
    /// `ERROR_INVALID_PARAMETER`, `candidate_of` returns the candidate it already
    /// had, and every package in the compatible-driver list is reported with an
    /// **empty INF file name** - `1 compatible package(s) exist for this node
    /// (:Apple, Inc.)`, a leading colon where `oem45.inf` should have been -
    /// while the process still exits successfully.
    ///
    /// Against that old code this test fails on the first loop iteration: a
    /// zeroed buffer reads back `cbSize == 0`, and `SetupAPI` rejects exactly
    /// that. The last two assertions state the defect literally, so the test
    /// cannot be satisfied by a buffer that merely happens to be zeroed.
    #[test]
    fn detail_buffer_always_carries_its_cb_size() {
        let struct_size = size_of::<SP_DRVINFO_DETAIL_DATA_W>();
        for asked in [0usize, 1, 4096] {
            let buf = detail_buffer(asked);
            assert!(
                buf.len() >= struct_size,
                "detail_buffer({asked}) returned {} bytes, smaller than the struct",
                buf.len()
            );
            assert_eq!(
                u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize,
                struct_size,
                "detail_buffer({asked}) left cbSize uninitialised"
            );
        }
        // The old code's buffer, spelled out: cbSize == 0, which is the value
        // SetupAPI refused.
        let defect = vec![0u8; 4096];
        assert_eq!(
            u32::from_le_bytes([defect[0], defect[1], defect[2], defect[3]]),
            0
        );
        assert_ne!(detail_buffer(4096)[..4], defect[..4]);
    }

    #[test]
    fn service_reads_prefer_the_registry_value_and_report_disagreement() {
        let n = Node {
            devprop_service: Some("WINUSB".to_string()),
            reg_service: Some("WINUSB".to_string()),
            ..Default::default()
        };
        assert_eq!(n.bound_service(), Some("WINUSB"));
        assert_eq!(n.service_kind(), ServiceKind::WinUsb);
        assert_eq!(n.reset_capability(), ResetCapability::No);
        assert!(!n.service_sources_disagree());

        let mid_change = Node {
            devprop_service: Some("libusbK".to_string()),
            reg_service: Some("WINUSB".to_string()),
            ..Default::default()
        };
        assert_eq!(mid_change.bound_service(), Some("WINUSB"));
        assert!(mid_change.service_sources_disagree());

        let empty = Node::default();
        assert_eq!(empty.bound_service(), None);
        assert_eq!(empty.service_kind(), ServiceKind::None);
    }

    #[test]
    fn bound_inf_prefers_the_property_and_falls_back_to_the_driver_subkey() {
        let a = Node {
            driver_inf: Some("oem45.inf".to_string()),
            reg_driver: Some("oem45.inf".to_string()),
            ..Default::default()
        };
        assert_eq!(a.bound_inf(), Some("oem45.inf"));
        let b = Node {
            driver_inf: None,
            reg_driver: Some("oem45.inf".to_string()),
            ..Default::default()
        };
        assert_eq!(b.bound_inf(), Some("oem45.inf"));
        let c = Node {
            driver_inf: Some(String::new()),
            reg_driver: Some("oem46.inf".to_string()),
            ..Default::default()
        };
        assert_eq!(c.bound_inf(), Some("oem46.inf"));
    }

    #[test]
    fn apple_serial_is_taken_from_the_instance_id() {
        let n = Node {
            instance_id:
                "USB\\VID_05AC&PID_1227\\CPID:8003_CPRV:01_BDID:02_ECID:00112233445566AA".to_string(),
            vid: APPLE_VID,
            pid: DFU_PID,
            ..Default::default()
        };
        let s = n.apple_serial().unwrap();
        assert!(s.starts_with("CPID:8003"));
        assert!(n.is_dfu());
    }

    #[test]
    fn masks_the_ecid_but_keeps_the_rest_of_the_descriptor() {
        let real = "USB\\VID_05AC&PID_1227\\CPID:8003_CPRV:01_CPFM:03_SCEP:01_BDID:02_ECID:00112233445566AA_IBFL:<redacted>_SRTG:[IBOOT-2234.0.0.2.22]";
        let masked = mask_ecid(real);
        assert!(!masked.contains("00112233445566AA"), "{masked}");
        assert!(masked.contains("ECID:00...66AA"), "{masked}");
        assert!(masked.contains("CPID:8003"));
        assert!(masked.contains("SRTG:[IBOOT-2234.0.0.2.22]"));
        // Nothing without an ECID is touched.
        assert_eq!(mask_ecid("USB\\VID_05AC&PID_024F"), "USB\\VID_05AC&PID_024F");
        // A short ECID is left alone rather than turned into noise.
        assert_eq!(mask_ecid("ECID:1234"), "ECID:1234");
    }

    #[test]
    fn masked_instance_ids_can_be_pasted_back_into_instance() {
        let real = "USB\\VID_05AC&PID_1227\\CPID:8003_CPRV:01_ECID:00112233445566AA_IBFL:<redacted>";
        let masked = mask_ecid(real);
        assert!(instance_matches(&masked, real));
        assert!(instance_matches(real, real));
        assert!(instance_matches("usb\\vid_05ac&pid_1227", real));
        assert!(!instance_matches("USB\\VID_05AC&PID_12A8", real));
        assert!(!instance_matches("CPID:8000", real));
    }

    #[test]
    fn selecting_a_node_refuses_to_guess_between_two_of_them() {
        let one = vec![node("USB\\A", true, DFU_PID)];
        assert_eq!(select_node(&one, DFU_PID, None, true).unwrap().instance_id, "USB\\A");

        let two = vec![node("USB\\A", true, DFU_PID), node("USB\\B", true, DFU_PID)];
        match select_node(&two, DFU_PID, None, true) {
            Err(SelectError::Ambiguous { instances }) => assert_eq!(instances.len(), 2),
            other => panic!("expected Ambiguous, got {other:?}"),
        }
        // ...but an explicit instance resolves it.
        assert_eq!(
            select_node(&two, DFU_PID, Some("usb\\b"), true)
                .unwrap()
                .instance_id,
            "USB\\B"
        );
    }

    #[test]
    fn selecting_ignores_ghost_nodes_when_presence_is_required() {
        // This mirrors the real machine: one present DFU node and one remembered
        // node from a previous unit.
        let nodes = vec![
            node("USB\\VID_05AC&PID_1227\\CPID:8003_PRESENT", true, DFU_PID),
            node("USB\\VID_05AC&PID_1227\\CPID:8000_GHOST", false, DFU_PID),
        ];
        let picked = select_node(&nodes, DFU_PID, None, true).unwrap();
        assert!(picked.instance_id.contains("PRESENT"));
        assert_eq!(
            select_node(&nodes, DFU_PID, None, false).unwrap_err(),
            SelectError::Ambiguous {
                instances: vec![
                    "USB\\VID_05AC&PID_1227\\CPID:8003_PRESENT".to_string(),
                    "USB\\VID_05AC&PID_1227\\CPID:8000_GHOST".to_string()
                ]
            }
        );
        assert_eq!(
            select_node(&nodes, 0x12A8, None, true).unwrap_err(),
            SelectError::NoneForPid { pid: 0x12A8 }
        );
        assert_eq!(
            select_node(&nodes, DFU_PID, Some("USB\\nope"), true).unwrap_err(),
            SelectError::NoSuchInstance {
                instance: "USB\\nope".to_string()
            }
        );
    }

    #[test]
    fn counts_only_present_devices_sharing_a_hardware_id() {
        let mut a = node("USB\\A", true, DFU_PID);
        a.hardware_ids = vec!["USB\\VID_05AC&PID_1227".to_string()];
        let mut b = node("USB\\B", true, DFU_PID);
        b.hardware_ids = vec!["USB\\VID_05AC&PID_1227".to_string()];
        let mut ghost = node("USB\\C", false, DFU_PID);
        ghost.hardware_ids = vec!["USB\\VID_05AC&PID_1227".to_string()];
        let nodes = vec![a, b, ghost];
        assert_eq!(count_present_with_hwid(&nodes, "usb\\vid_05ac&pid_1227"), 2);
        assert_eq!(count_present_with_hwid(&nodes, "USB\\VID_05AC&PID_12A8"), 0);
    }

    #[test]
    fn find_node_falls_back_to_a_unique_present_pid_match() {
        let nodes = vec![
            node("USB\\VID_05AC&PID_1227\\CPID:8003_A", true, DFU_PID),
            node("USB\\VID_05AC&PID_1227\\CPID:8000_B", false, DFU_PID),
        ];
        assert!(find_node(&nodes, "USB\\VID_05AC&PID_1227\\CPID:8003_A", DFU_PID).is_some());
        // The instance changed under us but exactly one present node matches.
        assert!(find_node(&nodes, "USB\\VID_05AC&PID_1227\\CPID:8003_A2", DFU_PID).is_some());
        let ambiguous = vec![
            node("USB\\VID_05AC&PID_1227\\X", true, DFU_PID),
            node("USB\\VID_05AC&PID_1227\\Y", true, DFU_PID),
        ];
        assert!(find_node(&ambiguous, "USB\\gone", DFU_PID).is_none());
        assert!(find_node(&nodes, "USB\\gone", 0x12A8).is_none());
    }
}
