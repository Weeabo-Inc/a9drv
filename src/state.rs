//! The rollback record.
//!
//! `bind` changes the host device tree. That is a privileged operation on
//! hardware the project cannot afford to lose, so before anything is written the
//! tool records what it found. `restore` reads this back. If the record is
//! missing, `restore` falls back to Apple's own package in the driver store and
//! says that it did.
//!
//! Format: one `key=value` per line. Deliberately not a binary blob and not
//! JSON: a person debugging a phone at 3am should be able to read and hand-edit
//! this file with `notepad`. Escaping is `\\`, `\n`, `\t` only, round-tripped in
//! the tests.

use std::path::{Path, PathBuf};

pub const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Written before the driver API is called.
    Prepared,
    /// The bind reported success and verification agreed.
    Bound,
    /// The previous binding was put back.
    Restored,
}

impl Phase {
    fn as_str(&self) -> &'static str {
        match self {
            Phase::Prepared => "prepared",
            Phase::Bound => "bound",
            Phase::Restored => "restored",
        }
    }

    fn parse(s: &str) -> Option<Phase> {
        match s {
            "prepared" => Some(Phase::Prepared),
            "bound" => Some(Phase::Bound),
            "restored" => Some(Phase::Restored),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackRecord {
    pub version: u32,
    pub phase: Phase,
    pub saved_unix: u64,
    /// The node the record is about. A record for a different instance is
    /// reported as such rather than applied blindly.
    pub instance_id: String,
    /// What was bound before we touched anything.
    pub previous_service: String,
    pub previous_inf: String,
    pub previous_provider: String,
    pub previous_version: String,
    /// What we bound instead.
    pub target_inf: String,
    pub target_service: String,
}

impl RollbackRecord {
    /// Build the "before" half of a record from a node.
    pub fn from_node(node: &crate::pnp::Node, target_inf: &str, target_service: &str) -> RollbackRecord {
        RollbackRecord {
            version: STATE_VERSION,
            phase: Phase::Prepared,
            saved_unix: now_unix(),
            instance_id: node.instance_id.clone(),
            previous_service: node.bound_service().unwrap_or("").to_string(),
            previous_inf: node.bound_inf().unwrap_or("").to_string(),
            previous_provider: node.provider.clone().unwrap_or_default(),
            previous_version: node.driver_version.clone().unwrap_or_default(),
            target_inf: target_inf.to_string(),
            target_service: target_service.to_string(),
        }
    }

    pub fn encode(&self) -> String {
        let mut out = String::new();
        out.push_str("# a9drv rollback record - see a9drv/README.md\n");
        out.push_str("# restore with: a9drv restore\n");
        let fields: [(&str, String); 10] = [
            ("version", self.version.to_string()),
            ("phase", self.phase.as_str().to_string()),
            ("saved_unix", self.saved_unix.to_string()),
            ("instance_id", self.instance_id.clone()),
            ("previous_service", self.previous_service.clone()),
            ("previous_inf", self.previous_inf.clone()),
            ("previous_provider", self.previous_provider.clone()),
            ("previous_version", self.previous_version.clone()),
            ("target_inf", self.target_inf.clone()),
            ("target_service", self.target_service.clone()),
        ];
        for (k, v) in fields {
            out.push_str(k);
            out.push('=');
            out.push_str(&escape(&v));
            out.push('\n');
        }
        out
    }

    pub fn decode(text: &str) -> Result<RollbackRecord, String> {
        let mut map: Vec<(String, String)> = Vec::new();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim_end_matches(['\r', '\n']);
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                return Err(format!("line {}: expected key=value, got {line:?}", lineno + 1));
            };
            map.push((k.trim().to_ascii_lowercase(), unescape(v)));
        }
        let get = |key: &str| -> Option<String> {
            map.iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.to_string())
        };
        let require = |key: &str| -> Result<String, String> {
            get(key).ok_or_else(|| format!("missing required key {key:?}"))
        };

        let version: u32 = require("version")?
            .parse()
            .map_err(|_| "version is not a number".to_string())?;
        if version != STATE_VERSION {
            return Err(format!(
                "record is version {version}, this build understands {STATE_VERSION}"
            ));
        }
        let phase_raw = require("phase")?;
        let phase = Phase::parse(&phase_raw)
            .ok_or_else(|| format!("unknown phase {phase_raw:?}"))?;
        let saved_unix: u64 = require("saved_unix")?
            .parse()
            .map_err(|_| "saved_unix is not a number".to_string())?;
        Ok(RollbackRecord {
            version,
            phase,
            saved_unix,
            instance_id: require("instance_id")?,
            previous_service: get("previous_service").unwrap_or_default(),
            previous_inf: get("previous_inf").unwrap_or_default(),
            previous_provider: get("previous_provider").unwrap_or_default(),
            previous_version: get("previous_version").unwrap_or_default(),
            target_inf: get("target_inf").unwrap_or_default(),
            target_service: get("target_service").unwrap_or_default(),
        })
    }
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            // Unknown escape: keep it verbatim rather than dropping bytes.
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `%A9DRV_STATE%`, else `%ProgramData%\a9drv\last-bind.conf`.
///
/// ProgramData rather than LocalAppData on purpose: the bind runs elevated and
/// the restore may run as the same user non-elevated, so the record has to live
/// somewhere both can read and that is not tied to one profile.
pub fn default_path() -> PathBuf {
    if let Some(p) = std::env::var_os("A9DRV_STATE") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("a9drv").join("last-bind.conf")
}

/// Write via a temporary file and rename, so an interrupted write cannot leave a
/// half-record that `restore` would misread.
pub fn save(path: &Path, rec: &RollbackRecord) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
    }
    let text = rec.encode();
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        format!(
            "cannot move {} into place at {}: {e}",
            tmp.display(),
            path.display()
        )
    })
}

/// `Ok(None)` means "no record", which is a normal state, not a failure.
pub fn load(path: &Path) -> Result<Option<RollbackRecord>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => RollbackRecord::decode(&text).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RollbackRecord {
        RollbackRecord {
            version: STATE_VERSION,
            phase: Phase::Prepared,
            saved_unix: 1_700_000_000,
            instance_id:
                r"USB\VID_05AC&PID_1227\CPID:8003_CPRV:01_CPFM:03_SCEP:01_BDID:02_ECID:00112233445566AA_IBFL:<redacted>_SRTG:[IBOOT-2234.0.0.2.22]"
                    .to_string(),
            previous_service: "WINUSB".to_string(),
            previous_inf: "oem45.inf".to_string(),
            previous_provider: "Apple, Inc.".to_string(),
            previous_version: "538.0.0.0".to_string(),
            target_inf: "oem46.inf".to_string(),
            target_service: "libusbK".to_string(),
        }
    }

    #[test]
    fn round_trips_the_real_field_values() {
        let rec = sample();
        let text = rec.encode();
        assert!(text.starts_with("# a9drv rollback record"));
        let back = RollbackRecord::decode(&text).expect("decodes");
        assert_eq!(back, rec);
    }

    #[test]
    fn round_trips_awkward_values() {
        let mut rec = sample();
        rec.previous_provider = r"a=b \ c".to_string();
        rec.previous_version = "line\nbreak\ttab".to_string();
        rec.previous_service = String::new();
        let back = RollbackRecord::decode(&rec.encode()).unwrap();
        assert_eq!(back, rec, "=, backslash and control characters must survive");
        assert_eq!(back.previous_service, "");
    }

    #[test]
    fn rejects_a_record_missing_required_keys() {
        let err = RollbackRecord::decode("version=1\nphase=bound\n").unwrap_err();
        assert!(err.contains("saved_unix") || err.contains("instance_id"), "{err}");
        let err2 = RollbackRecord::decode("instance_id=X\n").unwrap_err();
        assert!(err2.contains("version"), "{err2}");
    }

    #[test]
    fn rejects_unknown_phase_and_wrong_version() {
        let text = "version=1\nphase=halfway\nsaved_unix=1\ninstance_id=X\ntarget_inf=y\n";
        assert!(RollbackRecord::decode(text).unwrap_err().contains("phase"));
        let text2 = "version=99\nphase=bound\nsaved_unix=1\ninstance_id=X\ntarget_inf=y\n";
        assert!(RollbackRecord::decode(text2).unwrap_err().contains("99"));
    }

    #[test]
    fn ignores_comments_blank_lines_and_unknown_keys() {
        let text = "# comment\n\nversion=1\nphase=bound\nfuture_key=whatever\nsaved_unix=42\ninstance_id=A\ntarget_inf=oem46.inf\n";
        let rec = RollbackRecord::decode(text).unwrap();
        assert_eq!(rec.phase, Phase::Bound);
        assert_eq!(rec.saved_unix, 42);
        assert_eq!(rec.instance_id, "A");
    }

    #[test]
    fn rejects_lines_that_are_not_key_value() {
        let err = RollbackRecord::decode("this is not a record").unwrap_err();
        assert!(err.contains("key=value"), "{err}");
    }

    #[test]
    fn builds_the_previous_half_from_a_node() {
        let node = crate::pnp::Node {
            instance_id: "USB\\VID_05AC&PID_1227\\SER".to_string(),
            reg_service: Some("WINUSB".to_string()),
            driver_inf: Some("oem45.inf".to_string()),
            provider: Some("Apple, Inc.".to_string()),
            driver_version: Some("538.0.0.0".to_string()),
            ..Default::default()
        };
        let rec = RollbackRecord::from_node(&node, "oem46.inf", "libusbK");
        assert_eq!(rec.previous_service, "WINUSB");
        assert_eq!(rec.previous_inf, "oem45.inf");
        assert_eq!(rec.target_service, "libusbK");
        assert_eq!(rec.phase, Phase::Prepared);
        assert!(rec.saved_unix > 1_600_000_000);
    }

    #[test]
    fn missing_file_is_not_an_error() {
        let dir = std::env::temp_dir().join("a9drv-state-test-missing");
        let path = dir.join("nope.conf");
        let _ = std::fs::remove_file(&path);
        assert_eq!(load(&path).unwrap(), None);
    }

    #[test]
    fn saves_and_loads_through_the_filesystem() {
        let dir = std::env::temp_dir().join("a9drv-state-test-roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("last-bind.conf");
        let rec = sample();
        save(&path, &rec).expect("save");
        let back = load(&path).expect("load").expect("present");
        assert_eq!(back, rec);
        // The temp file used for the atomic rename must be gone.
        assert!(!path.with_extension("tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_path_is_under_program_data_or_the_override() {
        let p = default_path();
        if std::env::var_os("A9DRV_STATE").is_none() {
            assert!(
                p.to_string_lossy().to_lowercase().contains("a9drv"),
                "{p:?}"
            );
            assert!(p.to_string_lossy().ends_with("last-bind.conf"), "{p:?}");
        }
        assert!(!p.as_os_str().is_empty());
    }
}
