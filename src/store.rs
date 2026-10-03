//! Read-only inspection of the Windows **driver store** (`FileRepository`) and of
//! the INFs inside it.
//!
//! Why this module exists at all: on this host the signed libusbK package for
//! `USB\VID_05AC&PID_1227` is *already imported* into the driver store, so a9drv
//! does not have to carry, copy or install any driver binary - which is exactly
//! the capability difference over Zadig. Reading the store lets the tool say so
//! with evidence instead of asserting it, and gives `restore` a second source
//! for the package that has to go back.
//!
//! Everything here is a plain filesystem read. Nothing is written, and nothing
//! is loaded.

use std::path::{Path, PathBuf};

/// A package as it sits in `DriverStore\FileRepository`, e.g.
/// `apple_mobile_device_(dfu_mode).inf_amd64_3ea7093f7c96478f`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorePackage {
    /// Full folder name in FileRepository.
    pub folder: String,
    /// Original INF file name, e.g. `apple_mobile_device_(dfu_mode).inf`.
    pub original_inf: String,
    /// Architecture tag Windows used, e.g. `amd64`.
    pub arch: String,
    /// The store's content hash for the package.
    pub tag: String,
}

/// Which of the two packages a9drv knows how to reason about this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageRole {
    /// libwdi's generated INF for libusbK. Provider in the INF is `libusbK`.
    LibusbK,
    /// Apple's own `appleusb.inf`, the one that installs WinUSB for the DFU node.
    AppleWinUsb,
    Other,
}

/// Layout of a store folder name: `<original inf>_<arch>_<16 hex chars>`.
///
/// The original INF name itself can contain `(` `)` and `_`, so the split has to
/// be done from the right: the last two `_`-separated components are arch and
/// tag, everything before them is the INF name.
pub fn parse_folder(name: &str) -> Option<StorePackage> {
    let (stem, tag) = name.rsplit_once('_')?;
    if tag.len() != 16 || !tag.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let (original_inf, arch) = stem.rsplit_once('_')?;
    if original_inf.is_empty() || arch.is_empty() {
        return None;
    }
    if !original_inf.to_ascii_lowercase().ends_with(".inf") {
        return None;
    }
    Some(StorePackage {
        folder: name.to_string(),
        original_inf: original_inf.to_string(),
        arch: arch.to_string(),
        tag: tag.to_string(),
    })
}

/// Name-based role of a store package. Used for reporting and as a *fallback*
/// locator for `restore`; the authoritative answer for what a package provides
/// comes from the INF's own `Provider` and from SetupAPI's compatible-driver
/// list, not from this.
pub fn role(original_inf: &str) -> PackageRole {
    let n = original_inf.to_ascii_lowercase();
    if n == "apple_mobile_device_(dfu_mode).inf" {
        PackageRole::LibusbK
    } else if n == "appleusb.inf" {
        PackageRole::AppleWinUsb
    } else {
        PackageRole::Other
    }
}

pub fn file_repository() -> PathBuf {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    root.join("System32").join("DriverStore").join("FileRepository")
}

/// List the store folders. Read-only; a standard user can normally do this, and
/// a refusal is reported rather than worked around.
pub fn scan() -> Result<Vec<StorePackage>, String> {
    scan_in(&file_repository())
}

pub fn scan_in(dir: &Path) -> Result<Vec<StorePackage>, String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(pkg) = parse_folder(&name) {
            out.push(pkg);
        }
    }
    out.sort_by(|a, b| a.folder.cmp(&b.folder));
    Ok(out)
}

/// Only the packages relevant to this project: libusbK's generated INF and
/// Apple's own.
pub fn relevant(packages: &[StorePackage]) -> Vec<&StorePackage> {
    packages
        .iter()
        .filter(|p| role(&p.original_inf) != PackageRole::Other)
        .collect()
}

/// A few facts read straight out of an INF file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InfSummary {
    pub provider: Option<String>,
    pub driver_ver: Option<String>,
    pub class: Option<String>,
    pub catalog: Option<String>,
    /// Model lines that mention our device - the reason the package can be bound
    /// to this node at all.
    pub models: Vec<String>,
    /// LGPL/GPL mentions in the header comments. Reported because the licence
    /// position of a package we *select* is worth stating out loud.
    pub license_hints: Vec<String>,
}

/// Decode INF bytes. INF files are UTF-16LE with a BOM when a tool wrote them
/// with `WriteFile`+Unicode, and plain ANSI otherwise; both occur in the store.
pub fn decode_inf_bytes(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    if bytes.len() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
        return String::from_utf8_lossy(&bytes[3..]).to_string();
    }
    String::from_utf8_lossy(bytes).to_string()
}

/// Replace `%TOKEN%` with the value from the INF's `[Strings]` section.
///
/// This is not decorative. The libusbK INF states its model line as
///
/// ```text
/// DeviceID = "VID_05AC&PID_1227"          ; [Strings]
/// %DeviceName%=LUsbK_Device, USB\%DeviceID%   ; [Manufacturer] group
/// ```
///
/// so a literal search for the device ID finds the *string table* entry and
/// misses the model line - which is the line that proves the package can bind to
/// this node. Unknown tokens are left alone rather than blanked, so a missing
/// string shows up as `%FOO%` instead of silently reading as empty.
pub fn expand_strings(line: &str, strings: &[(String, String)]) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('%') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let key = after[..end].to_ascii_uppercase();
        match strings.iter().find(|(k, _)| *k == key) {
            Some((_, v)) => out.push_str(v),
            None => {
                out.push('%');
                out.push_str(&after[..end]);
                out.push('%');
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Parse the parts of an INF that a9drv reports. Forgiving on purpose: a store
/// INF with an odd encoding must not make the tool fail, it must make it say less.
pub fn parse_inf_summary(text: &str, device_marker: &str) -> InfSummary {
    // A BOM survives into the string whenever an INF is decoded without the
    // BOM-aware path above, and it lands in front of the first line - which in
    // these INFs is the licence comment. Strip it, or the first line is lost.
    let text = text.trim_start_matches('\u{feff}');
    let mut out = InfSummary::default();
    let mut section = String::new();
    let marker = device_marker.to_ascii_lowercase();
    let mut strings: Vec<(String, String)> = Vec::new();
    // Lines that might mention the device once %TOKEN% is expanded.
    let mut pending: Vec<String> = Vec::new();
    let mut version_keys: Vec<(String, String)> = Vec::new();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with(';') {
            let low = line.to_ascii_lowercase();
            if (low.contains("lgpl") || low.contains("gnu") || low.contains("general public"))
                && out.license_hints.len() < 4
            {
                out.license_hints
                    .push(line.trim_start_matches(';').trim().to_string());
            }
            continue;
        }
        if line.starts_with('[') {
            section = line
                .trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            continue;
        }
        let pair = line.split_once('=').map(|(k, v)| {
            (
                k.trim().to_string(),
                v.trim().trim_matches('"').to_string(),
            )
        });
        if section == "strings" {
            if let Some((k, v)) = pair {
                strings.push((k.to_ascii_uppercase(), v));
            }
            continue;
        }
        if section == "version" {
            if let Some(kv) = pair.clone() {
                version_keys.push(kv);
            }
        }
        pending.push(line.to_string());
    }

    for (k, v) in &version_keys {
        let val = expand_strings(v, &strings);
        match k.to_ascii_lowercase().as_str() {
            "provider" => out.provider = Some(val),
            "driverver" => out.driver_ver = Some(val),
            "class" => out.class = Some(val),
            "catalogfile" => out.catalog = Some(val),
            _ => {}
        }
    }

    if !marker.is_empty() {
        for line in &pending {
            let expanded = expand_strings(line, &strings);
            if expanded.to_ascii_lowercase().contains(&marker) && out.models.len() < 8 {
                out.models.push(expanded);
            }
        }
    }
    out
}

/// Read and summarise `<folder>\<original_inf>` inside the store.
pub fn read_inf_summary(pkg: &StorePackage, device_marker: &str) -> Option<InfSummary> {
    let path = file_repository().join(&pkg.folder).join(&pkg.original_inf);
    let bytes = std::fs::read(&path).ok()?;
    Some(parse_inf_summary(&decode_inf_bytes(&bytes), device_marker))
}

/// A package as Windows publishes it: `%SystemRoot%\INF\oemNN.inf`.
///
/// This is the *selection* source, and that is a measured decision rather than a
/// preference. On this host `SetupDiBuildDriverInfoList(SPDIT_COMPATDRIVER)` -
/// Windows' own "compatible drivers" list for the DFU node - returns exactly one
/// package: Apple's `oem45.inf`. The libusbK packages, despite being in the store
/// with a model line for `USB\VID_05AC&PID_1227`, are not in it. So a tool that
/// asks Windows which drivers are compatible will conclude "nothing available"
/// on the one machine where two signed libusbK packages are sitting ready.
///
/// The published INFs are read directly instead: file contents, provider,
/// DriverVer and the model lines, all from disk, no API opinion involved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPackage {
    /// `oem46.inf`.
    pub published_name: String,
    /// `%SystemRoot%\INF\oem46.inf`.
    pub path: PathBuf,
    pub provider: String,
    pub class: String,
    pub catalog: String,
    /// Raw `[Version] DriverVer`, e.g. `06/13/2024, 3.1.0.0`.
    pub driver_ver_raw: String,
    /// `2024-06-13`.
    pub date: String,
    /// `3.1.0.0`.
    pub version: String,
    /// Model lines that claim this device. Non-empty is what makes a package a
    /// candidate at all.
    pub models: Vec<String>,
    pub license_hints: Vec<String>,
}

pub fn system_root() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

pub fn inf_directory() -> PathBuf {
    system_root().join("INF")
}

/// `06/13/2024, 3.1.0.0` -> (`2024-06-13`, `3.1.0.0`).
///
/// A date that cannot be parsed is passed through as written: a date a9drv
/// cannot normalise is still a date worth printing.
pub fn parse_driver_ver(raw: &str) -> (String, String) {
    let mut parts = raw.splitn(2, ',');
    let date_raw = parts.next().unwrap_or("").trim();
    let version = parts.next().unwrap_or("").trim().to_string();
    let date = match date_raw.split('/').collect::<Vec<_>>().as_slice() {
        [m, d, y] => {
            let m: u32 = m.trim().parse().unwrap_or(0);
            let d: u32 = d.trim().parse().unwrap_or(0);
            let y = y.trim();
            if (1..=12).contains(&m) && (1..=31).contains(&d) && y.len() == 4 {
                format!("{y}-{m:02}-{d:02}")
            } else {
                date_raw.to_string()
            }
        }
        _ => date_raw.to_string(),
    };
    (date, version)
}

/// Every published `oemNN.inf` in `%SystemRoot%\INF` that claims the device.
pub fn scan_published(device_marker: &str) -> Result<Vec<PublishedPackage>, String> {
    scan_published_in(&inf_directory(), device_marker)
}

pub fn scan_published_in(dir: &Path, device_marker: &str) -> Result<Vec<PublishedPackage>, String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let lower = name.to_ascii_lowercase();
        if !lower.starts_with("oem") || !lower.ends_with(".inf") {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        let summary = parse_inf_summary(&decode_inf_bytes(&bytes), device_marker);
        if summary.models.is_empty() {
            // Does not claim this device. Most of %SystemRoot%\INF lands here.
            continue;
        }
        let raw = summary.driver_ver.clone().unwrap_or_default();
        let (date, version) = parse_driver_ver(&raw);
        out.push(PublishedPackage {
            published_name: name,
            path: entry.path(),
            provider: summary.provider.clone().unwrap_or_default(),
            class: summary.class.clone().unwrap_or_default(),
            catalog: summary.catalog.clone().unwrap_or_default(),
            driver_ver_raw: raw,
            date,
            version,
            models: summary.models.clone(),
            license_hints: summary.license_hints.clone(),
        });
    }
    out.sort_by(|a, b| {
        published_index(&a.published_name)
            .cmp(&published_index(&b.published_name))
            .then_with(|| a.published_name.cmp(&b.published_name))
    });
    Ok(out)
}

/// The numeric part of a published name, for deterministic ordering.
pub fn published_index(name: &str) -> u32 {
    let lower = name.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("oem") else {
        return u32::MAX;
    };
    rest.chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(u32::MAX)
}

/// Does the driver store hold a staged copy of this published INF?
///
/// Matched on provider and the raw `DriverVer` string, which is what ties the
/// published copy to its `FileRepository` folder. Used for provenance reporting,
/// so that "the package is already in the store" is a measurement, not a claim.
pub fn staged_copy<'a>(
    packages: &'a [StorePackage],
    provider: &str,
    driver_ver_raw: &str,
    device_marker: &str,
) -> Option<&'a StorePackage> {
    packages.iter().find(|p| {
        read_inf_summary(p, device_marker)
            .map(|s| {
                s.provider
                    .as_deref()
                    .map(|sp| sp.eq_ignore_ascii_case(provider))
                    .unwrap_or(false)
                    && s.driver_ver.as_deref() == Some(driver_ver_raw)
            })
            .unwrap_or(false)
    })
}

/// The INF path a driver-store folder would be installed from.
pub fn store_inf_path(pkg: &StorePackage) -> PathBuf {
    file_repository().join(&pkg.folder).join(&pkg.original_inf)
}

/// Turn a published INF into the selection type, so the decision logic has one
/// shape to work with regardless of where the package description came from.
pub fn as_candidate(pkg: &PublishedPackage) -> crate::pnp::Candidate {
    crate::pnp::Candidate {
        inf_file: pkg.published_name.clone(),
        path: Some(pkg.path.clone()),
        source: crate::pnp::CandidateSource::PublishedInf,
        section: pkg
            .models
            .first()
            .and_then(|m| m.split_once('=').map(|(_, rhs)| rhs))
            .and_then(|rhs| rhs.split(',').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
        description: if pkg.class.is_empty() {
            pkg.models.first().cloned().unwrap_or_default()
        } else {
            pkg.class.clone()
        },
        mfg: pkg.provider.clone(),
        provider: pkg.provider.clone(),
        version: pkg.version.clone(),
        date: pkg.date.clone(),
        hardware_id: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_store_folder_names_from_this_host() {
        // Measured: these three folders exist in
        // C:\Windows\System32\DriverStore\FileRepository on this machine.
        let a = parse_folder("apple_mobile_device_(dfu_mode).inf_amd64_3ea7093f7c96478f").unwrap();
        assert_eq!(a.original_inf, "apple_mobile_device_(dfu_mode).inf");
        assert_eq!(a.arch, "amd64");
        assert_eq!(a.tag, "3ea7093f7c96478f");
        assert_eq!(role(&a.original_inf), PackageRole::LibusbK);

        let b = parse_folder("apple_mobile_device_(dfu_mode).inf_amd64_efc2f87eb321e3dc").unwrap();
        assert_eq!(b.original_inf, "apple_mobile_device_(dfu_mode).inf");
        assert_ne!(a.tag, b.tag);

        let c = parse_folder("appleusb.inf_amd64_58854158183af679").unwrap();
        assert_eq!(c.original_inf, "appleusb.inf");
        assert_eq!(role(&c.original_inf), PackageRole::AppleWinUsb);
    }

    #[test]
    fn rejects_folders_that_are_not_store_packages() {
        assert!(parse_folder("nvidia").is_none());
        assert!(parse_folder("foo.inf_amd64").is_none());
        assert!(parse_folder("foo.inf_amd64_nothexatall").is_none());
        assert!(parse_folder("foo_amd64_0123456789abcdef").is_none()); // no .inf
        assert!(parse_folder("").is_none());
    }

    #[test]
    fn role_matching_is_case_insensitive() {
        assert_eq!(role("Apple_Mobile_Device_(DFU_Mode).INF"), PackageRole::LibusbK);
        assert_eq!(role("AppleUSB.INF"), PackageRole::AppleWinUsb);
        assert_eq!(role("nvme.inf"), PackageRole::Other);
    }

    #[test]
    fn decodes_utf16le_with_bom_and_ansi() {
        let mut utf16 = vec![0xFF, 0xFE];
        for u in "Provider = \"libusbK\"".encode_utf16() {
            utf16.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(decode_inf_bytes(&utf16), "Provider = \"libusbK\"");
        assert_eq!(
            decode_inf_bytes(b"Provider = \"libusbK\""),
            "Provider = \"libusbK\""
        );
        let utf8bom = [b"\xEF\xBB\xBF".as_slice(), b"Class = X"].concat();
        assert_eq!(decode_inf_bytes(&utf8bom), "Class = X");
    }

    /// The structure of these two INFs is taken from the real files on this host:
    /// oem46.inf is UTF-16 with a `[Version]` block, and oem45.inf carries
    /// `Include=winusb.inf / Needs=WINUSB.NT` for PID_1227.
    #[test]
    fn summarises_a_libusbk_style_inf() {
        let text = "\u{feff}; Copyright (c) 2011-2012 libusbK (GNU LGPL)\n\
                    \n\
                    [Strings]\n\
                    DeviceName = \"Apple Mobile Device (DFU Mode)\"\n\
                    DeviceID   = \"VID_05AC&PID_1227\"\n\
                    \n\
                    [Version]\n\
                    Signature   = \"$Windows NT$\"\n\
                    Class       = \"libusbk devices\"\n\
                    Provider    = \"libusbK\"\n\
                    CatalogFile = Apple_Mobile_Device_(DFU_Mode).cat\n\
                    DriverVer   = 06/13/2024, 3.1.0.0\n\
                    \n\
                    [LUsbK_DeviceGroup.NTAMD64]\n\
                    %DeviceName%=LUsbK_Device, USB\\%DeviceID%\n";
        let s = parse_inf_summary(text, "VID_05AC&PID_1227");
        assert_eq!(s.provider.as_deref(), Some("libusbK"));
        assert_eq!(s.driver_ver.as_deref(), Some("06/13/2024, 3.1.0.0"));
        assert_eq!(s.class.as_deref(), Some("libusbk devices"));
        assert_eq!(s.catalog.as_deref(), Some("Apple_Mobile_Device_(DFU_Mode).cat"));
        assert_eq!(s.models.len(), 1, "the DeviceID string in [Strings] is not a model line");
        assert!(s.models[0].contains("LUsbK_Device"));
        assert_eq!(s.license_hints.len(), 1);
        assert!(s.license_hints[0].contains("LGPL"));
    }

    #[test]
    fn summarises_an_apple_style_inf_and_finds_the_winusb_include() {
        let text = "; Installation inf for the Apple Mobile Device driver\n\
                    [Version]\n\
                    Class=USBDevice\n\
                    Provider=%AAPL%\n\
                    DriverVer = 06/14/2023,538.0.0.0\n\
                    CatalogFile=AppleUSB.cat\n\
                    [Apple.NTamd64]\n\
                    %iDFU.AppleUsbMux.DeviceDesc%=AppleUsbMux_Install, USB\\VID_05ac&PID_1227\n\
                    [AppleUsbMux_Install.NT]\n\
                    Include=winusb.inf\n\
                    Needs=WINUSB.NT\n";
        let s = parse_inf_summary(text, "VID_05AC&PID_1227");
        assert_eq!(s.class.as_deref(), Some("USBDevice"));
        assert_eq!(s.provider.as_deref(), Some("%AAPL%"));
        assert_eq!(s.driver_ver.as_deref(), Some("06/14/2023,538.0.0.0"));
        assert_eq!(s.models.len(), 1);
    }

    #[test]
    fn expands_string_table_tokens_and_leaves_unknown_ones_visible() {
        let strings = vec![
            ("DEVICEID".to_string(), "VID_05AC&PID_1227".to_string()),
            ("DEVICENAME".to_string(), "Apple Mobile Device (DFU Mode)".to_string()),
        ];
        assert_eq!(
            expand_strings("%DeviceName%=LUsbK_Device, USB\\%DeviceID%", &strings),
            "Apple Mobile Device (DFU Mode)=LUsbK_Device, USB\\VID_05AC&PID_1227"
        );
        // An unresolvable token stays as written: a missing string must be
        // visible, not silently empty.
        assert_eq!(expand_strings("Provider=%AAPL%", &strings), "Provider=%AAPL%");
        assert_eq!(expand_strings("no tokens here", &strings), "no tokens here");
        assert_eq!(expand_strings("trailing %", &strings), "trailing %");
    }

    #[test]
    fn parse_is_forgiving_about_garbage() {
        let s = parse_inf_summary("\u{0}\u{1}not an inf at all", "VID_05AC");
        assert_eq!(s, InfSummary::default());
        let s2 = parse_inf_summary("", "VID_05AC");
        assert_eq!(s2, InfSummary::default());
    }

    #[test]
    fn filters_to_relevant_packages_only() {
        let pkgs: Vec<StorePackage> = [
            "appleusb.inf_amd64_58854158183af679",
            "apple_mobile_device_(dfu_mode).inf_amd64_3ea7093f7c96478f",
            "nvme.inf_amd64_aaaaaaaaaaaaaaaa",
        ]
        .iter()
        .filter_map(|n| parse_folder(n))
        .collect();
        let rel = relevant(&pkgs);
        assert_eq!(rel.len(), 2);
        assert!(rel.iter().all(|p| role(&p.original_inf) != PackageRole::Other));
    }

    /// Where the candidates come from. This is fix (a) of the rebind that would
    /// not happen, pinned without SetupAPI and without the device.
    ///
    /// `a9drv` used to draw its candidates **only** from
    /// `SetupDiBuildDriverInfoList(SPDIT_COMPATDRIVER)`, Windows' own
    /// compatible-driver list for the node. Measured on this host, that list
    /// contains exactly one package for the DFU node - Apple's - even though two
    /// signed libusbK packages are in the driver store with a model line for
    /// `USB\VID_05AC&PID_1227`. So libusbK was never a candidate at all, and the
    /// tool reported "No usable driver package in the driver store" on the one
    /// machine where the right package was sitting ready.
    ///
    /// The selection source is now the published INFs in `%SystemRoot%\INF`, read
    /// from disk. A libusbK-style INF has to be recognised there even with an
    /// *empty* Windows list - which is what this directory layout stands in for -
    /// and that includes the `%DeviceID%` indirection, the reason the model line
    /// cannot be found by searching the INF text for the device ID.
    #[test]
    fn published_infs_are_a_selection_source_without_the_compat_list() {
        let dir = std::env::temp_dir().join(format!("a9drv-published-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the fixture INF directory");

        // libusbK's generated INF, in the shape the store on this host has it.
        std::fs::write(
            dir.join("oem46.inf"),
            "[Strings]\n\
             DeviceName = \"Apple Mobile Device (DFU Mode)\"\n\
             DeviceID   = \"VID_05AC&PID_1227\"\n\
             [Version]\n\
             Class       = \"libusbk devices\"\n\
             Provider    = \"libusbK\"\n\
             CatalogFile = Apple_Mobile_Device_(DFU_Mode).cat\n\
             DriverVer   = 06/13/2024, 3.1.0.0\n\
             [LUsbK_DeviceGroup.NTAMD64]\n\
             %DeviceName%=LUsbK_Device, USB\\%DeviceID%\n",
        )
        .expect("write oem46.inf");
        // Apple's own INF: the one package Windows' list does offer for this node.
        std::fs::write(
            dir.join("oem45.inf"),
            "[Version]\n\
             Class=USBDevice\n\
             Provider=%AAPL%\n\
             DriverVer = 06/14/2023,538.0.0.0\n\
             [Apple.NTamd64]\n\
             %iDFU.AppleUsbMux.DeviceDesc%=AppleUsbMux_Install, USB\\VID_05ac&PID_1227\n",
        )
        .expect("write oem45.inf");
        // Anything else published. `%SystemRoot%\INF` is full of these and none
        // of them may become a candidate for this node.
        std::fs::write(
            dir.join("oem99.inf"),
            "[Version]\n\
             Class=SCSIAdapter\n\
             Provider=%VENDOR%\n\
             [Vendor.NTamd64]\n\
             %Adapter%=Adapter_Install, PCI\\VEN_1234&DEV_5678\n",
        )
        .expect("write oem99.inf");

        let found = scan_published_in(&dir, "VID_05AC&PID_1227").expect("scan the directory");
        let names: Vec<&str> = found.iter().map(|p| p.published_name.as_str()).collect();
        // Numeric order, so the pick is deterministic; the unrelated package is
        // not a candidate at all.
        assert_eq!(names, vec!["oem45.inf", "oem46.inf"]);

        let libusbk = found
            .iter()
            .find(|p| p.published_name == "oem46.inf")
            .expect("the libusbK package must be found with an empty Windows compat list");
        assert_eq!(libusbk.provider, "libusbK");
        assert_eq!(libusbk.class, "libusbk devices");
        assert_eq!(libusbk.version, "3.1.0.0");
        assert_eq!(libusbk.date, "2024-06-13");
        assert!(
            libusbk.models[0].contains("USB\\VID_05AC&PID_1227"),
            "the model line has to survive [Strings] expansion: {:?}",
            libusbk.models
        );

        // ...and it becomes a PublishedInf candidate naming the published file,
        // which is the identity `bind --inf` and the plan both use.
        let candidate = as_candidate(libusbk);
        let inf46 = dir.join("oem46.inf");
        assert_eq!(candidate.inf_file, "oem46.inf");
        assert_eq!(candidate.source, crate::pnp::CandidateSource::PublishedInf);
        assert_eq!(candidate.path.as_deref(), Some(inf46.as_path()));
        assert_eq!(candidate.provider, "libusbK");
        assert_eq!(candidate.mfg, "libusbK");
        assert_eq!(candidate.version, "3.1.0.0");
        assert_eq!(candidate.date, "2024-06-13");
        assert_eq!(candidate.section, "LUsbK_Device");
        assert_eq!(candidate.description, "libusbk devices");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
