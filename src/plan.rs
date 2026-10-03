//! What the tool is going to do, decided before it does anything.
//!
//! Every function here is pure: given the node, the driver-store candidates and
//! the rollback record, it returns an action. No Win32 call, no I/O. That is what
//! makes "state what it will do before doing it" a property of the code rather
//! than a print statement someone has to remember to keep in sync - and it is
//! what makes the decisions unit-testable on a machine with no phone attached.

use crate::classify::ServiceKind;
use crate::pnp::{Candidate, Node};
use crate::state::RollbackRecord;

/// Which driver family the caller wants bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preference {
    LibusbK,
    Libusb0,
    WinUsb,
}

impl Preference {
    pub fn parse(s: &str) -> Option<Preference> {
        match s.trim().to_ascii_lowercase().as_str() {
            "libusbk" | "libusb-k" => Some(Preference::LibusbK),
            "libusb0" | "libusb-win32" | "libusb" => Some(Preference::Libusb0),
            "winusb" | "apple" => Some(Preference::WinUsb),
            _ => None,
        }
    }

    /// The service name the package is expected to install. Used for the plan
    /// text and for post-bind verification.
    pub fn target_service(&self) -> &'static str {
        match self {
            Preference::LibusbK => "libusbK",
            Preference::Libusb0 => "libusb0",
            Preference::WinUsb => "WINUSB",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Preference::LibusbK => "libusbK",
            Preference::Libusb0 => "libusb0",
            Preference::WinUsb => "WinUSB (Apple's binding)",
        }
    }

    /// Does a driver-store package provide this family?
    ///
    /// Matched on the INF's `Provider` (and description for the libusb families),
    /// which is what the store publishes; never on the file name, because the
    /// libusbK package's file name (`apple_mobile_device_(dfu_mode).inf`) says
    /// nothing about libusbK. The WinUSB/Apple preference matches on the provider
    /// alone: the libusbK package's *description* also says "Apple Mobile Device
    /// (DFU Mode)", so matching on it would make Apple's driver and libusbK
    /// indistinguishable.
    pub fn matches(&self, c: &Candidate) -> bool {
        let provider = c.provider.to_ascii_lowercase();
        let hay = format!("{} {}", c.provider, c.description).to_ascii_lowercase();
        match self {
            Preference::LibusbK => hay.contains("libusbk"),
            Preference::Libusb0 => {
                hay.contains("libusb0") || hay.contains("libusb-win32") || hay.contains("libusb-0")
            }
            Preference::WinUsb => provider.contains("apple") || provider.contains("winusb"),
        }
    }
}

/// Is this the package Apple ships for the DFU node?
pub fn is_apple_package(c: &Candidate) -> bool {
    c.provider.to_ascii_lowercase().contains("apple")
}

/// The published name's numeric part, for a deterministic pick when the store
/// holds two copies of the same package.
fn oem_index(inf_file: &str) -> u32 {
    let lower = inf_file.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("oem") else {
        return u32::MAX;
    };
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().unwrap_or(u32::MAX)
}

/// Choose deterministically, and explain the choice.
///
/// This host has **two** published copies of the same libusbK package:
/// `oem46.inf` and `oem47.inf`, byte-identical except for the
/// `DeviceInterfaceGUID` in their string table. Left to chance, two runs could
/// pick different ones and the tool would look non-deterministic. Lowest
/// published number wins, and the alternatives are always reported.
pub fn choose<'a>(candidates: &'a [Candidate], prefer: Preference) -> Option<(&'a Candidate, Vec<&'a Candidate>)> {
    let mut matches: Vec<&Candidate> = candidates.iter().filter(|c| prefer.matches(c)).collect();
    if matches.is_empty() {
        return None;
    }
    matches.sort_by(|a, b| {
        oem_index(&a.inf_file)
            .cmp(&oem_index(&b.inf_file))
            .then_with(|| a.inf_file.cmp(&b.inf_file))
    });
    let chosen = matches[0];
    let rest = matches[1..].to_vec();
    Some((chosen, rest))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindAction {
    /// The node is already bound to the requested family. Show the plan, do
    /// nothing, exit 0. Running the tool twice must be safe.
    AlreadyBound { service: String },
    /// Force this store package onto this node.
    Select {
        inf_file: String,
        provider: String,
        version: String,
        target_service: String,
        alternatives: Vec<String>,
    },
    /// Nothing in the driver store provides the requested family.
    NoMatchingPackage { detail: String },
}

/// Decide what `bind` will do.
pub fn decide_bind(
    node: &Node,
    candidates: &[Candidate],
    prefer: Preference,
    explicit_inf: Option<&str>,
) -> BindAction {
    let current = node.bound_service().unwrap_or("");
    let kind = ServiceKind::parse(current);

    // An explicit --inf overrides everything except "not a driver package".
    if let Some(inf) = explicit_inf {
        if kind.is_checkm8_transport() && same_inf(node.bound_inf(), inf) {
            return BindAction::AlreadyBound {
                service: current.to_string(),
            };
        }
        let provider = candidates
            .iter()
            .find(|c| c.inf_file.eq_ignore_ascii_case(inf))
            .map(|c| c.provider.clone())
            .unwrap_or_else(|| "(from --inf)".to_string());
        let version = candidates
            .iter()
            .find(|c| c.inf_file.eq_ignore_ascii_case(inf))
            .map(|c| c.version.clone())
            .unwrap_or_default();
        return BindAction::Select {
            inf_file: inf.to_string(),
            provider,
            version,
            target_service: prefer.target_service().to_string(),
            alternatives: Vec::new(),
        };
    }

    if kind == ServiceKind::parse(prefer.target_service()) {
        return BindAction::AlreadyBound {
            service: current.to_string(),
        };
    }

    match choose(candidates, prefer) {
        Some((chosen, rest)) => BindAction::Select {
            inf_file: chosen.inf_file.clone(),
            provider: chosen.provider.clone(),
            version: chosen.version.clone(),
            target_service: prefer.target_service().to_string(),
            alternatives: rest.iter().map(|c| c.inf_file.clone()).collect(),
        },
        None => BindAction::NoMatchingPackage {
            detail: if candidates.is_empty() {
                "the driver store returned no compatible driver for this node at all".to_string()
            } else {
                format!(
                    "{} compatible package(s) exist for this node ({}) but none of them provides {}",
                    candidates.len(),
                    candidates
                        .iter()
                        .map(|c| format!("{}:{}", c.inf_file, c.provider))
                        .collect::<Vec<_>>()
                        .join(", "),
                    prefer.label()
                )
            },
        },
    }
}

/// Where a restore target came from, so the report can say it out loud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreSource {
    /// The INF recorded before the bind.
    Record { inf_file: String },
    /// Apple's own package, found in the driver store by hand.
    DriverStore,
    /// The caller passed `--inf`.
    Explicit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreAction {
    /// libusbK is not bound, so the node is not ours to restore.
    NothingToRestore { service: String },
    Select {
        inf_file: String,
        provider: String,
        version: String,
        source: RestoreSource,
        target_service: String,
    },
    NoSource { detail: String },
}

/// Decide what `restore` will do.
pub fn decide_restore(
    node: &Node,
    candidates: &[Candidate],
    record: Option<&RollbackRecord>,
    explicit_inf: Option<&str>,
) -> RestoreAction {
    let current = node.bound_service().unwrap_or("");
    let kind = ServiceKind::parse(current);

    if let Some(inf) = explicit_inf {
        let provider = candidates
            .iter()
            .find(|c| c.inf_file.eq_ignore_ascii_case(inf))
            .map(|c| c.provider.clone())
            .unwrap_or_else(|| "(from --inf)".to_string());
        let version = candidates
            .iter()
            .find(|c| c.inf_file.eq_ignore_ascii_case(inf))
            .map(|c| c.version.clone())
            .unwrap_or_default();
        return RestoreAction::Select {
            inf_file: inf.to_string(),
            provider,
            version,
            source: RestoreSource::Explicit,
            target_service: String::new(),
        };
    }

    // If nothing reset-capable is bound, there is nothing of ours to undo.
    if !kind.is_checkm8_transport() {
        return RestoreAction::NothingToRestore {
            service: current.to_string(),
        };
    }

    if let Some(rec) = record {
        if !rec.previous_inf.is_empty() {
            let candidate = candidates
                .iter()
                .find(|c| c.inf_file.eq_ignore_ascii_case(&rec.previous_inf));
            return RestoreAction::Select {
                inf_file: rec.previous_inf.clone(),
                provider: candidate
                    .map(|c| c.provider.clone())
                    .unwrap_or_else(|| rec.previous_provider.clone()),
                version: candidate
                    .map(|c| c.version.clone())
                    .unwrap_or_else(|| rec.previous_version.clone()),
                source: RestoreSource::Record {
                    inf_file: rec.previous_inf.clone(),
                },
                target_service: rec.previous_service.clone(),
            };
        }
    }

    // No usable record: fall back to Apple's package, which is the only thing
    // this node was ever bound to before we touched it.
    let apple: Vec<&Candidate> = candidates.iter().filter(|c| is_apple_package(c)).collect();
    match apple.len() {
        0 => RestoreAction::NoSource {
            detail: "no rollback record, and the driver store returned no Apple package for this \
                     node - use --inf to name the INF to restore"
                .to_string(),
        },
        _ => {
            let mut sorted = apple;
            sorted.sort_by(|a, b| {
                oem_index(&a.inf_file)
                    .cmp(&oem_index(&b.inf_file))
                    .then_with(|| a.inf_file.cmp(&b.inf_file))
            });
            let chosen = sorted[0];
            RestoreAction::Select {
                inf_file: chosen.inf_file.clone(),
                provider: chosen.provider.clone(),
                version: chosen.version.clone(),
                source: RestoreSource::DriverStore,
                target_service: "WINUSB".to_string(),
            }
        }
    }
}

fn same_inf(bound: Option<&str>, wanted: &str) -> bool {
    match bound {
        Some(b) => {
            let b = b.rsplit(['\\', '/']).next().unwrap_or(b);
            b.eq_ignore_ascii_case(wanted)
        }
        None => false,
    }
}

/// What `verify` was asked to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    LibusbK,
    Libusb0,
    WinUsb,
    /// Whatever the rollback record says was there before.
    Restored,
}

impl Expect {
    pub fn parse(s: &str) -> Option<Expect> {
        match s.trim().to_ascii_lowercase().as_str() {
            "libusbk" | "libusb-k" => Some(Expect::LibusbK),
            "libusb0" | "libusb-win32" | "libusb" => Some(Expect::Libusb0),
            "winusb" | "apple" => Some(Expect::WinUsb),
            "restored" | "previous" => Some(Expect::Restored),
            _ => None,
        }
    }

    pub fn wants_service(&self) -> Option<&'static str> {
        match self {
            Expect::LibusbK => Some("libusbK"),
            Expect::Libusb0 => Some("libusb0"),
            Expect::WinUsb => Some("WINUSB"),
            Expect::Restored => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    Pass {
        service: String,
        wanted: String,
        transport: bool,
    },
    Fail {
        service: Option<String>,
        wanted: String,
        detail: String,
    },
    /// The check itself could not be made - not a failure of the device.
    CannotVerify { wanted: String, detail: String },
}

/// Decide whether the node is in the state `verify` was asked about.
pub fn decide_verify(node: &Node, expect: Expect, record: Option<&RollbackRecord>) -> VerifyOutcome {
    let current = node.bound_service().unwrap_or("").to_string();
    let kind = ServiceKind::parse(&current);

    match expect {
        Expect::LibusbK | Expect::Libusb0 => {
            if !kind.is_checkm8_transport() {
                return VerifyOutcome::Fail {
                    service: Some(current.clone()),
                    wanted: "libusbK or libusb0".to_string(),
                    detail: format!(
                        "checkm8 needs a libusb-family driver; this node is bound to {:?} ({})",
                        current,
                        kind.reset_capability_text()
                    ),
                };
            }
            if kind != ServiceKind::parse(expect.wants_service().unwrap()) {
                return VerifyOutcome::Fail {
                    service: Some(current.clone()),
                    wanted: expect.wants_service().unwrap().to_string(),
                    detail: format!(
                        "a reset-capable driver is bound, but it is {} and {} was asked for",
                        kind.name(),
                        expect.wants_service().unwrap()
                    ),
                };
            }
            VerifyOutcome::Pass {
                service: current,
                wanted: expect.wants_service().unwrap().to_string(),
                transport: true,
            }
        }
        Expect::WinUsb => {
            if kind == ServiceKind::WinUsb {
                VerifyOutcome::Pass {
                    service: current,
                    wanted: "WINUSB".to_string(),
                    transport: false,
                }
            } else {
                VerifyOutcome::Fail {
                    service: Some(current.clone()),
                    wanted: "WINUSB".to_string(),
                    detail: format!("this node is bound to {current:?}, not to Apple's WinUSB binding"),
                }
            }
        }
        Expect::Restored => match record {
            None => VerifyOutcome::CannotVerify {
                wanted: "the binding recorded in the rollback file".to_string(),
                detail: "no rollback record exists, so there is nothing to compare against".to_string(),
            },
            Some(rec) => {
                let previous = rec.previous_service.clone();
                if previous.is_empty() {
                    if !kind.is_checkm8_transport() {
                        VerifyOutcome::Pass {
                            service: current,
                            wanted: "(nothing - the node had no driver)".to_string(),
                            transport: false,
                        }
                    } else {
                        VerifyOutcome::Fail {
                            service: Some(current.clone()),
                            wanted: "(nothing - the node had no driver)".to_string(),
                            detail: "the record says the node had no driver bound, and it does now"
                                .to_string(),
                        }
                    }
                } else if current.eq_ignore_ascii_case(&previous) {
                    VerifyOutcome::Pass {
                        service: current,
                        wanted: previous,
                        transport: kind.is_checkm8_transport(),
                    }
                } else {
                    VerifyOutcome::Fail {
                        service: Some(current.clone()),
                        wanted: previous,
                        detail: "the node is not back to the binding the rollback record describes"
                            .to_string(),
                    }
                }
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pnp::{Candidate, Node};

    fn dfu_node(service: &str, inf: Option<&str>) -> Node {
        Node {
            instance_id: "USB\\VID_05AC&PID_1227\\CPID:8003_SER".to_string(),
            device_desc: "Apple Mobile Device USB Device".to_string(),
            hardware_ids: vec![
                "USB\\VID_05AC&PID_1227&REV_0000".to_string(),
                "USB\\VID_05AC&PID_1227".to_string(),
            ],
            reg_service: Some(service.to_string()),
            devprop_service: Some(service.to_string()),
            driver_inf: inf.map(|s| s.to_string()),
            reg_driver: inf.map(|s| s.to_string()),
            provider: Some("Apple, Inc.".to_string()),
            driver_version: Some("538.0.0.0".to_string()),
            present: true,
            vid: 0x05AC,
            pid: 0x1227,
            ..Default::default()
        }
    }

    /// The three packages this host really has in its driver store.
    fn real_candidates() -> Vec<Candidate> {
        let mut apple = Candidate::synthetic("oem45.inf", "Apple, Inc.", "538.0.0.0");
        apple.description = "Apple Mobile Device USB Device".to_string();
        vec![
            apple,
            Candidate::synthetic("oem46.inf", "libusbK", "3.1.0.0"),
            Candidate::synthetic("oem47.inf", "libusbK", "3.1.0.0"),
        ]
    }

    #[test]
    fn preference_parsing_accepts_the_spellings_people_type() {
        assert_eq!(Preference::parse("libusbK"), Some(Preference::LibusbK));
        assert_eq!(Preference::parse("LIBUSBK"), Some(Preference::LibusbK));
        assert_eq!(Preference::parse(" libusb0 "), Some(Preference::Libusb0));
        assert_eq!(Preference::parse("winusb"), Some(Preference::WinUsb));
        assert_eq!(Preference::parse("apple"), Some(Preference::WinUsb));
        assert_eq!(Preference::parse("nonsense"), None);
        assert_eq!(Preference::LibusbK.target_service(), "libusbK");
        assert_eq!(Preference::Libusb0.target_service(), "libusb0");
    }

    #[test]
    fn preference_matching_uses_the_provider_not_the_file_name() {
        let cands = real_candidates();
        let k: Vec<&str> = cands
            .iter()
            .filter(|c| Preference::LibusbK.matches(c))
            .map(|c| c.inf_file.as_str())
            .collect();
        assert_eq!(k, vec!["oem46.inf", "oem47.inf"]);
        let w: Vec<&str> = cands
            .iter()
            .filter(|c| Preference::WinUsb.matches(c))
            .map(|c| c.inf_file.as_str())
            .collect();
        assert_eq!(w, vec!["oem45.inf"]);
        // The libusbK package's *description* mentions Apple; matching the WinUSB
        // preference on it would have made the two packages indistinguishable.
        assert!(cands[1].description.contains("Apple"));
        assert!(!Preference::WinUsb.matches(&cands[1]));
        // ...and the libusbK package's *file* name mentions Apple and DFU too,
        // which is why matching is done on the provider.
        assert!(Preference::Libusb0.matches(&cands[1]) == false);
    }

    #[test]
    fn picks_the_lowest_published_copy_deterministically() {
        let cands = real_candidates();
        let (chosen, rest) = choose(&cands, Preference::LibusbK).unwrap();
        assert_eq!(chosen.inf_file, "oem46.inf");
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].inf_file, "oem47.inf");

        // Order in the store listing must not change the answer.
        let mut shuffled = cands.clone();
        shuffled.reverse();
        assert_eq!(choose(&shuffled, Preference::LibusbK).unwrap().0.inf_file, "oem46.inf");
    }

    #[test]
    fn bind_on_a_winusb_node_selects_the_libusbk_package() {
        let action = decide_bind(&dfu_node("WINUSB", Some("oem45.inf")), &real_candidates(), Preference::LibusbK, None);
        match action {
            BindAction::Select { inf_file, provider, version, target_service, alternatives } => {
                assert_eq!(inf_file, "oem46.inf");
                assert_eq!(provider, "libusbK");
                assert_eq!(version, "3.1.0.0");
                assert_eq!(target_service, "libusbK");
                assert_eq!(alternatives, vec!["oem47.inf".to_string()]);
            }
            other => panic!("expected Select, got {other:?}"),
        }
    }

    #[test]
    fn bind_is_idempotent_when_libusbk_is_already_bound() {
        let action = decide_bind(&dfu_node("libusbK", Some("oem46.inf")), &real_candidates(), Preference::LibusbK, None);
        assert_eq!(
            action,
            BindAction::AlreadyBound {
                service: "libusbK".to_string()
            }
        );
    }

    #[test]
    fn bind_distinguishes_no_package_from_wrong_package() {
        let none = decide_bind(&dfu_node("WINUSB", Some("oem45.inf")), &[], Preference::LibusbK, None);
        match none {
            BindAction::NoMatchingPackage { detail } => {
                assert!(detail.contains("no compatible driver"), "{detail}");
            }
            other => panic!("expected NoMatchingPackage, got {other:?}"),
        }

        // Packages exist, but only Apple's: that is a different situation and
        // gets a different sentence.
        let only_apple = real_candidates()[..1].to_vec();
        match decide_bind(&dfu_node("WINUSB", Some("oem45.inf")), &only_apple, Preference::LibusbK, None) {
            BindAction::NoMatchingPackage { detail } => {
                assert!(detail.contains("none of them provides"), "{detail}");
                assert!(detail.contains("oem45.inf:Apple, Inc."), "{detail}");
            }
            other => panic!("expected NoMatchingPackage, got {other:?}"),
        }
    }

    #[test]
    fn bind_honours_an_explicit_inf() {
        let action = decide_bind(
            &dfu_node("WINUSB", Some("oem45.inf")),
            &real_candidates(),
            Preference::LibusbK,
            Some("oem47.inf"),
        );
        match action {
            BindAction::Select { inf_file, provider, .. } => {
                assert_eq!(inf_file, "oem47.inf");
                assert_eq!(provider, "libusbK");
            }
            other => panic!("expected Select, got {other:?}"),
        }
    }

    #[test]
    fn bind_can_target_libusb0_and_says_so_when_the_store_has_none() {
        let action = decide_bind(&dfu_node("WINUSB", None), &real_candidates(), Preference::Libusb0, None);
        match action {
            BindAction::NoMatchingPackage { detail } => assert!(detail.contains("libusb0"), "{detail}"),
            other => panic!("expected NoMatchingPackage, got {other:?}"),
        }
    }

    fn record() -> RollbackRecord {
        RollbackRecord {
            version: crate::state::STATE_VERSION,
            phase: crate::state::Phase::Bound,
            saved_unix: 1_700_000_000,
            instance_id: "USB\\VID_05AC&PID_1227\\CPID:8003_SER".to_string(),
            previous_service: "WINUSB".to_string(),
            previous_inf: "oem45.inf".to_string(),
            previous_provider: "Apple, Inc.".to_string(),
            previous_version: "538.0.0.0".to_string(),
            target_inf: "oem46.inf".to_string(),
            target_service: "libusbK".to_string(),
        }
    }

    #[test]
    fn restore_uses_the_recorded_inf() {
        match decide_restore(&dfu_node("libusbK", Some("oem46.inf")), &real_candidates(), Some(&record()), None) {
            RestoreAction::Select { inf_file, source, target_service, provider, .. } => {
                assert_eq!(inf_file, "oem45.inf");
                assert_eq!(source, RestoreSource::Record { inf_file: "oem45.inf".to_string() });
                assert_eq!(target_service, "WINUSB");
                assert_eq!(provider, "Apple, Inc.");
            }
            other => panic!("expected Select, got {other:?}"),
        }
    }

    #[test]
    fn restore_falls_back_to_the_store_and_says_it_did() {
        match decide_restore(&dfu_node("libusbK", Some("oem46.inf")), &real_candidates(), None, None) {
            RestoreAction::Select { inf_file, source, .. } => {
                assert_eq!(inf_file, "oem45.inf");
                assert_eq!(source, RestoreSource::DriverStore);
            }
            other => panic!("expected Select, got {other:?}"),
        }
    }

    #[test]
    fn restore_refuses_when_there_is_neither_record_nor_apple_package() {
        let only_libusbk = real_candidates()[1..].to_vec();
        match decide_restore(&dfu_node("libusbK", Some("oem46.inf")), &only_libusbk, None, None) {
            RestoreAction::NoSource { detail } => assert!(detail.contains("--inf"), "{detail}"),
            other => panic!("expected NoSource, got {other:?}"),
        }
    }

    #[test]
    fn restore_is_a_no_op_when_nothing_reset_capable_is_bound() {
        assert_eq!(
            decide_restore(&dfu_node("WINUSB", Some("oem45.inf")), &real_candidates(), Some(&record()), None),
            RestoreAction::NothingToRestore {
                service: "WINUSB".to_string()
            }
        );
    }

    #[test]
    fn verify_expects_libusbk_by_default_semantics() {
        let pass = decide_verify(&dfu_node("libusbK", Some("oem46.inf")), Expect::LibusbK, None);
        assert_eq!(
            pass,
            VerifyOutcome::Pass {
                service: "libusbK".to_string(),
                wanted: "libusbK".to_string(),
                transport: true
            }
        );

        match decide_verify(&dfu_node("WINUSB", Some("oem45.inf")), Expect::LibusbK, None) {
            VerifyOutcome::Fail { service, detail, .. } => {
                assert_eq!(service.as_deref(), Some("WINUSB"));
                assert!(detail.contains("WinUSB cannot reset the port"), "{detail}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }

        // libusb0 satisfies "reset-capable" but not "libusbK was asked for".
        match decide_verify(&dfu_node("libusb0", None), Expect::LibusbK, None) {
            VerifyOutcome::Fail { detail, .. } => assert!(detail.contains("libusb0"), "{detail}"),
            other => panic!("expected Fail, got {other:?}"),
        }
        assert!(matches!(
            decide_verify(&dfu_node("libusb0", None), Expect::Libusb0, None),
            VerifyOutcome::Pass { .. }
        ));
    }

    #[test]
    fn verify_winusb_and_restored_expectations() {
        assert!(matches!(
            decide_verify(&dfu_node("WINUSB", Some("oem45.inf")), Expect::WinUsb, None),
            VerifyOutcome::Pass { transport: false, .. }
        ));
        assert!(matches!(
            decide_verify(&dfu_node("libusbK", None), Expect::WinUsb, None),
            VerifyOutcome::Fail { .. }
        ));
        assert!(matches!(
            decide_verify(&dfu_node("WINUSB", Some("oem45.inf")), Expect::Restored, Some(&record())),
            VerifyOutcome::Pass { .. }
        ));
        assert!(matches!(
            decide_verify(&dfu_node("libusbK", None), Expect::Restored, Some(&record())),
            VerifyOutcome::Fail { .. }
        ));
        // Without a record there is nothing to compare against, and that is said
        // rather than turned into a pass.
        match decide_verify(&dfu_node("WINUSB", None), Expect::Restored, None) {
            VerifyOutcome::CannotVerify { detail, .. } => assert!(detail.contains("no rollback record")),
            other => panic!("expected CannotVerify, got {other:?}"),
        }
    }

    #[test]
    fn expect_parsing_covers_the_cli_spellings() {
        assert_eq!(Expect::parse("libusbK"), Some(Expect::LibusbK));
        assert_eq!(Expect::parse("libusb0"), Some(Expect::Libusb0));
        assert_eq!(Expect::parse("winusb"), Some(Expect::WinUsb));
        assert_eq!(Expect::parse("restored"), Some(Expect::Restored));
        assert_eq!(Expect::parse("previous"), Some(Expect::Restored));
        assert_eq!(Expect::parse("maybe"), None);
        assert_eq!(Expect::Restored.wants_service(), None);
    }

    #[test]
    fn oem_index_orders_published_names_numerically() {
        assert!(oem_index("oem46.inf") < oem_index("oem47.inf"));
        assert!(oem_index("oem9.inf") < oem_index("oem10.inf"));
        assert_eq!(oem_index("appleusb.inf"), u32::MAX);
    }
}
