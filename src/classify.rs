//! Classification of the driver **service** a device node is bound to.
//!
//! This is the whole reason the tool exists, so it lives in one place, has no
//! I/O, and is unit-tested against the exact strings Windows produces.
//!
//! # Why the bound service decides whether checkm8 can run at all
//!
//! checkm8 performs a host-initiated USB port reset after every stage attempt.
//! That reset is not a convenience: it is the trigger that runs the overwritten
//! bootrom callback. libusb on Windows implements `libusb_reset_device` by
//! asking the bound kernel driver to do it:
//!
//! ```text
//! libusb1-sys-0.7.0/libusb/libusb/os/windows_winusb.c:3412
//!   // libusbK & libusb0 have the ability to issue an actual device reset
//!   if ((sub_api != SUB_API_WINUSB) && (WinUSBX[sub_api].ResetDevice != NULL)) {
//!       ...
//!       WinUSBX[sub_api].ResetDevice(winusb_handle);
//!   }
//!   return LIBUSB_SUCCESS;      // <- line 3419: success is returned either way
//! ```
//!
//! On WinUSB the reset degrades to aborting and resetting the pipes and still
//! returns `LIBUSB_SUCCESS`. The host believes it reset the port; the port was
//! never reset; the bootrom's callback never runs. The visible symptom is an
//! endless pad-request `TIMEOUT` where the exploit needs a `STALL` - which reads
//! like an exploit bug and is a driver-binding fact.
//!
//! So the service name is not a curiosity. `libusbK`/`libusb0` -> usable,
//! `WINUSB` -> the trap.

/// The driver service a device node is bound to, reduced to what matters here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKind {
    /// libusbK: calls `ResetDevice`. This is the target.
    LibusbK,
    /// libusb0 / libusb-win32: also calls `ResetDevice`.
    Libusb0,
    /// WinUSB: cannot reset the port, reports success anyway. The trap.
    WinUsb,
    /// usbccgp: composite parent. libusb cannot claim the DFU function one level up.
    Composite,
    /// usbhub / usbhub3: the hub itself, not a device.
    Hub,
    /// Apple's own service names (AppleUsbFilter, AppleUsbMux, ...).
    Apple,
    /// No service value at all: the node has no function driver bound.
    None,
    /// Something else. Reported verbatim, never guessed at.
    Other,
}

/// Can a driver with this service perform a host-initiated port reset?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetCapability {
    /// libusbK / libusb0: calls `ResetDevice`. checkm8 can run.
    Yes,
    /// WinUSB: does not. checkm8 cannot run, and reports a misleading failure.
    No,
    /// Not a libusb-family driver, so libusb cannot open the node either.
    Unusable,
    /// Unrecognised service name. Unknown, and said to be unknown.
    Unknown,
}

impl ServiceKind {
    /// Classify a service string exactly as Windows stores it.
    ///
    /// Matching is case-insensitive and tolerates surrounding whitespace, which
    /// is what registry reads produce. Order matters only in that `libusbk` and
    /// `libusb0` are checked before anything that could contain `libusb`.
    pub fn parse(service: &str) -> ServiceKind {
        let s = service.trim().to_ascii_lowercase();
        if s.is_empty() {
            return ServiceKind::None;
        }
        if s.contains("libusbk") {
            return ServiceKind::LibusbK;
        }
        // "libusb0", "libusb-win32", and the bare "libusb" some filter packages use.
        if s.contains("libusb0") || s.contains("libusb-0") || s.contains("libusb-win32") || s == "libusb"
        {
            return ServiceKind::Libusb0;
        }
        if s.contains("winusb") {
            return ServiceKind::WinUsb;
        }
        if s.contains("usbccgp") {
            return ServiceKind::Composite;
        }
        if s.contains("usbhub") {
            return ServiceKind::Hub;
        }
        if s.starts_with("apple") {
            return ServiceKind::Apple;
        }
        ServiceKind::Other
    }

    /// Stable machine-readable name, used in `--json`.
    pub fn name(&self) -> &'static str {
        match self {
            ServiceKind::LibusbK => "libusbK",
            ServiceKind::Libusb0 => "libusb0",
            ServiceKind::WinUsb => "WINUSB",
            ServiceKind::Composite => "usbccgp",
            ServiceKind::Hub => "usbhub",
            ServiceKind::Apple => "apple",
            ServiceKind::None => "none",
            ServiceKind::Other => "other",
        }
    }

    pub fn reset_capability(&self) -> ResetCapability {
        match self {
            ServiceKind::LibusbK | ServiceKind::Libusb0 => ResetCapability::Yes,
            ServiceKind::WinUsb => ResetCapability::No,
            ServiceKind::Composite | ServiceKind::Hub | ServiceKind::Apple | ServiceKind::None => {
                ResetCapability::Unusable
            }
            ServiceKind::Other => ResetCapability::Unknown,
        }
    }

    /// One line a human can act on.
    pub fn reset_capability_text(&self) -> &'static str {
        match self.reset_capability() {
            ResetCapability::Yes => "YES - checkm8 can run",
            ResetCapability::No => "NO - WinUSB cannot reset the port, and lies about it",
            ResetCapability::Unusable => "NO - libusb cannot claim this node",
            ResetCapability::Unknown => "? - unrecognised driver",
        }
    }

    /// True for the only two services libusb can both open *and* reset.
    pub fn is_checkm8_transport(&self) -> bool {
        matches!(self, ServiceKind::LibusbK | ServiceKind::Libusb0)
    }
}

impl ResetCapability {
    pub fn name(&self) -> &'static str {
        match self {
            ResetCapability::Yes => "yes",
            ResetCapability::No => "no",
            ResetCapability::Unusable => "unusable",
            ResetCapability::Unknown => "unknown",
        }
    }
}

/// Is this service the specific trap we are trying to get out of?
pub fn is_still_winusb(service: Option<&str>) -> bool {
    matches!(service.map(ServiceKind::parse), Some(ServiceKind::WinUsb))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_the_services_this_host_actually_has() {
        // Measured on this host: oem45.inf (Apple) installs
        // `Include=winusb.inf / Needs=WINUSB.NT`, and the DFU node's Service
        // value reads WINUSB.
        assert_eq!(ServiceKind::parse("WINUSB"), ServiceKind::WinUsb);
        assert_eq!(ServiceKind::parse("libusbK"), ServiceKind::LibusbK);
    }

    #[test]
    fn classification_is_case_insensitive_and_trimmed() {
        for s in ["LIBUSBK", "libusbk", "  libusbK  ", "LibusbK"] {
            assert_eq!(ServiceKind::parse(s), ServiceKind::LibusbK, "{s:?}");
        }
        for s in ["winusb", "WinUSB", " WINUSB "] {
            assert_eq!(ServiceKind::parse(s), ServiceKind::WinUsb, "{s:?}");
        }
    }

    #[test]
    fn libusb0_family_is_recognised_and_not_confused_with_libusbk() {
        assert_eq!(ServiceKind::parse("libusb0"), ServiceKind::Libusb0);
        assert_eq!(ServiceKind::parse("libusb-win32"), ServiceKind::Libusb0);
        assert_eq!(ServiceKind::parse("libusb-0"), ServiceKind::Libusb0);
        assert_eq!(ServiceKind::parse("libusb"), ServiceKind::Libusb0);
        // A libusbK name must never fall into the libusb0 bucket.
        assert_eq!(ServiceKind::parse("libusbK.sys"), ServiceKind::LibusbK);
    }

    #[test]
    fn parent_and_hub_and_apple_services_are_not_transports() {
        assert_eq!(ServiceKind::parse("usbccgp"), ServiceKind::Composite);
        assert_eq!(ServiceKind::parse("USBCCGP"), ServiceKind::Composite);
        assert_eq!(ServiceKind::parse("usbhub"), ServiceKind::Hub);
        assert_eq!(ServiceKind::parse("USBHUB3"), ServiceKind::Hub);
        assert_eq!(ServiceKind::parse("AppleUsbFilter"), ServiceKind::Apple);
        assert_eq!(ServiceKind::parse("AppleUsbMux"), ServiceKind::Apple);
        for s in ["usbccgp", "usbhub3", "AppleUsbFilter"] {
            assert!(!ServiceKind::parse(s).is_checkm8_transport(), "{s}");
        }
    }

    #[test]
    fn empty_and_unknown_services_are_reported_not_guessed() {
        assert_eq!(ServiceKind::parse(""), ServiceKind::None);
        assert_eq!(ServiceKind::parse("   "), ServiceKind::None);
        assert_eq!(ServiceKind::parse("USBSTOR"), ServiceKind::Other);
        assert_eq!(ServiceKind::parse("UASPStor"), ServiceKind::Other);
        assert_eq!(ServiceKind::parse("USBSTOR").reset_capability(), ResetCapability::Unknown);
    }

    #[test]
    fn only_libusb_family_services_can_reset_the_port() {
        assert_eq!(ServiceKind::parse("libusbK").reset_capability(), ResetCapability::Yes);
        assert_eq!(ServiceKind::parse("libusb0").reset_capability(), ResetCapability::Yes);
        assert_eq!(ServiceKind::parse("WINUSB").reset_capability(), ResetCapability::No);
        assert_eq!(ServiceKind::parse("").reset_capability(), ResetCapability::Unusable);
        assert_eq!(ServiceKind::parse("usbccgp").reset_capability(), ResetCapability::Unusable);
    }

    #[test]
    fn the_trap_predicate_matches_winusb_only() {
        assert!(is_still_winusb(Some("WINUSB")));
        assert!(is_still_winusb(Some("winusb")));
        assert!(!is_still_winusb(Some("libusbK")));
        assert!(!is_still_winusb(Some("")));
        assert!(!is_still_winusb(None));
    }

    #[test]
    fn names_are_stable_for_json_consumers() {
        assert_eq!(ServiceKind::parse("libusbK").name(), "libusbK");
        assert_eq!(ServiceKind::parse("WINUSB").name(), "WINUSB");
        assert_eq!(ServiceKind::parse("").name(), "none");
        assert_eq!(ServiceKind::parse("").reset_capability().name(), "unusable");
    }
}
