//! a9drv - bind the Apple A9 DFU node to libusbK, prove it, and be able to undo it.
//!
//! # Why this exists
//!
//! checkm8 performs a **host-initiated USB bus reset** after every stage attempt.
//! That reset is not housekeeping: it is the trigger that runs the overwritten
//! bootrom callback. On Windows that reset is performed by the bound kernel
//! driver, and libusb only asks for it when the driver is libusbK or libusb0:
//!
//! ```text
//! libusb1-sys-0.7.0/libusb/libusb/os/windows_winusb.c
//!  3371  /* ... "WinUSB does not support host-initiated reset port and cycle
//!           port operations" ... the best we can do is cycle the pipes */
//!  3412  // libusbK & libusb0 have the ability to issue an actual device reset
//!  3413  if ((sub_api != SUB_API_WINUSB) && (WinUSBX[sub_api].ResetDevice != NULL)) {
//!  3416      WinUSBX[sub_api].ResetDevice(winusb_handle);
//!  3417  }
//!  3419  return LIBUSB_SUCCESS;      <- success is returned even when it did nothing
//! ```
//!
//! So with the stock Apple binding (`appleusb.inf`, `Service=WINUSB`) the reset
//! silently becomes a pipe cycle, the trigger never fires, and the exploit reports
//! an endless pad-request TIMEOUT where it needs a STALL. The message blames the
//! exploit; the cause is the driver binding.
//!
//! # What this tool does about it
//!
//! It forces an **already-present, already-signed** driver package from the
//! Windows driver store onto the DFU node and then *re-reads the bound driver
//! service* to prove it. It is a replacement for Zadig, and the difference is not
//! cosmetic: Zadig (through libwdi) must carry driver binaries and install them.
//! On this host the required package is already in the store, so a9drv ships no
//! driver at all - it selects, verifies, and can put the previous binding back.
//!
//! `list` and `verify` read only. `bind` and `restore` change the host device
//! tree and therefore demand an elevated console; a9drv never self-elevates.

mod apply;
mod classify;
mod cli;
mod elevate;
mod json;
mod pnp;
mod plan;
mod state;
mod store;

use std::process::ExitCode;
use std::time::{Duration, Instant};

use apply::Method;
use cli::{Args, Sub};
use json::J;
use pnp::{Candidate, Node};
use plan::{BindAction, Expect, RestoreAction, RestoreSource, VerifyOutcome};

const EXIT_OK: u8 = 0;
const EXIT_INTERNAL: u8 = 1;
const EXIT_VERIFY_FAILED: u8 = 2;
const EXIT_NEEDS_ELEVATION: u8 = 3;
const EXIT_NO_DEVICE: u8 = 4;
const EXIT_BIND_REFUSED: u8 = 5;
const EXIT_NO_PACKAGE: u8 = 6;
const EXIT_USAGE: u8 = 7;
const EXIT_STATE: u8 = 8;

/// How long to keep re-reading after a driver change. The node is restarted by
/// the install, so it disappears from enumeration for a moment and comes back;
/// reading once would produce a false failure.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// failures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Fail {
    Elevation(&'static str),
    NoDevice {
        pid: u16,
        ghosts: Vec<String>,
    },
    NotPresent {
        instance: String,
    },
    Ambiguous {
        instances: Vec<String>,
    },
    NoPackage {
        detail: String,
    },
    Refused {
        method: Method,
        win32: u32,
        detail: String,
        achieved: Option<String>,
    },
    StillWinUsb {
        method: Method,
        win32: u32,
        api_ok: bool,
        achieved: Option<String>,
    },
    VerifyFailed {
        detail: String,
        achieved: Option<String>,
    },
    State(String),
    Internal(String),
    Usage(String),
}

impl Fail {
    fn exit_code(&self) -> u8 {
        match self {
            Fail::Elevation(_) => EXIT_NEEDS_ELEVATION,
            Fail::NoDevice { .. } | Fail::NotPresent { .. } | Fail::Ambiguous { .. } => {
                EXIT_NO_DEVICE
            }
            Fail::NoPackage { .. } => EXIT_NO_PACKAGE,
            Fail::Refused { .. } => EXIT_BIND_REFUSED,
            Fail::StillWinUsb { api_ok, .. } => {
                if *api_ok {
                    EXIT_VERIFY_FAILED
                } else {
                    EXIT_BIND_REFUSED
                }
            }
            Fail::VerifyFailed { .. } => EXIT_VERIFY_FAILED,
            Fail::State(_) => EXIT_STATE,
            Fail::Internal(_) => EXIT_INTERNAL,
            Fail::Usage(_) => EXIT_USAGE,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Fail::Elevation(_) => "needs_elevation",
            Fail::NoDevice { .. } => "no_device",
            Fail::NotPresent { .. } => "not_present",
            Fail::Ambiguous { .. } => "ambiguous_device",
            Fail::NoPackage { .. } => "no_matching_package",
            Fail::Refused { .. } => "binding_refused",
            Fail::StillWinUsb { .. } => "still_winusb",
            Fail::VerifyFailed { .. } => "verify_failed",
            Fail::State(_) => "state_file",
            Fail::Internal(_) => "internal",
            Fail::Usage(_) => "usage",
        }
    }

    fn win32(&self) -> Option<u32> {
        match self {
            Fail::Refused { win32, .. } | Fail::StillWinUsb { win32, .. } => {
                Some(*win32)
            }
            _ => None,
        }
    }

    /// One line, for `--json` and for the summary line of a human report.
    fn flat(&self) -> String {
        match self {
            Fail::Elevation(m) => (*m).to_string(),
            Fail::NoDevice { pid, .. } => format!("no present node with PID {pid:04X}"),
            Fail::NotPresent { instance } => format!("device node {instance} is not present"),
            Fail::Ambiguous { instances } => {
                format!("{} nodes match; use --instance", instances.len())
            }
            Fail::NoPackage { detail } => detail.clone(),
            Fail::Refused { method, win32, detail, .. } => format!(
                "{} refused (Win32 {win32}: {}): {detail}",
                method.name(),
                apply::win32_explain(*win32)
            ),
            Fail::StillWinUsb { .. } => {
                "the node is STILL bound to WINUSB; checkm8 cannot run".to_string()
            }
            Fail::VerifyFailed { detail, .. } => detail.clone(),
            Fail::State(m) | Fail::Internal(m) | Fail::Usage(m) => m.clone(),
        }
    }

    /// The human report. Loud where it has to be, and always says what to do next.
    fn human(&self) -> String {
        match self {
            Fail::Elevation(m) => (*m).to_string(),
            Fail::NoDevice { pid, ghosts } => {
                let mut s = format!(
                    "No present device node with PID {pid:04X}.\n  \
                     Plug the phone in, put it in DFU mode, then run `a9drv list` to see every \
                     Apple-VID node."
                );
                if !ghosts.is_empty() {
                    s.push_str(&format!(
                        "\n  Windows still remembers {} node(s) with this PID from earlier sessions \
                         (not present now):",
                        ghosts.len()
                    ));
                    for g in ghosts {
                        s.push_str(&format!("\n    {g}"));
                    }
                    s.push_str("\n  Those are ghosts. They cannot be bound and are not the problem.");
                }
                s
            }
            Fail::NotPresent { instance } => format!(
                "Device node {instance} exists but is not present.\n  \
                 Nothing was changed. `a9drv list --all` shows remembered nodes."
            ),
            Fail::Ambiguous { instances } => {
                let mut s = String::from(
                    "More than one node matches, so a9drv will not guess which one to bind. Pass \
                     --instance with one of:",
                );
                for i in instances {
                    s.push_str(&format!("\n    {i}"));
                }
                s
            }
            Fail::NoPackage { detail } => format!(
                "No usable driver package in the driver store.\n  {detail}\n  \
                 This is NOT a refusal by Windows: there was nothing to bind.\n  \
                 `a9drv list` prints every package the store offers for this node."
            ),
            Fail::Refused { method, win32, detail, achieved } => format!(
                "The driver API refused the bind.\n  \
                 method      : {}\n  \
                 Win32       : {win32} ({})\n  \
                 detail      : {detail}\n  \
                 bound now   : {}\n  \
                 The package exists, so this is a refusal rather than a missing package.\n  \
                 Try the other API:  a9drv bind --method {}\n  \
                 Or undo everything: a9drv restore",
                method.label(),
                apply::win32_explain(*win32),
                achieved.as_deref().unwrap_or("(node not enumerated)"),
                method.other().name()
            ),
            Fail::StillWinUsb { method, win32, api_ok, achieved } => {
                let mut s = String::from("FAILED - THE NODE IS STILL BOUND TO WINUSB.\n");
                s.push_str(&format!(
                    "  the driver API   : {} {}\n",
                    method.label(),
                    if *api_ok {
                        "reported success".to_string()
                    } else {
                        format!("reported failure, Win32 {win32} ({})", apply::win32_explain(*win32))
                    }
                ));
                s.push_str(&format!(
                    "  bound service now: {}\n",
                    achieved.as_deref().unwrap_or("(node not enumerated)")
                ));
                s.push_str(
                    "  checkm8 CANNOT run in this state. Under WinUSB, libusb's reset degrades to a\n  \
                     pipe cycle and still returns LIBUSB_SUCCESS (windows_winusb.c:3412-3419), so the\n  \
                     reset that is supposed to trigger the overwritten bootrom callback never happens.\n  \
                     The exploit will report a pad-request TIMEOUT where it needs a STALL, and that\n  \
                     message is about the driver, not about the exploit.\n  \
                     next:\n    \
                     a9drv bind --method update     retry with the hardware-ID-scoped API\n    \
                     a9drv list --all               every Apple-VID node and its bound service\n    \
                     a9drv restore                  put the previous binding back",
                );
                s
            }
            Fail::VerifyFailed { detail, achieved } => format!(
                "VERIFY FAILED.\n  {detail}\n  bound service now: {}\n  \
                 next: a9drv list   (see every Apple-VID node and what it is bound to)",
                achieved.as_deref().unwrap_or("(node not enumerated)")
            ),
            Fail::State(m) => format!(
                "Rollback file problem: {m}\n  \
                 The rollback file records what to go back to. Without it `a9drv restore` can only \
                 fall back to Apple's package from the driver store."
            ),
            Fail::Internal(m) => format!("Internal error: {m}"),
            Fail::Usage(m) => format!("{m}"),
        }
    }
}

// ---------------------------------------------------------------------------
// output plumbing
// ---------------------------------------------------------------------------

struct Out {
    json: bool,
    lines: Vec<String>,
    obj: J,
    notes: Vec<String>,
}

impl Out {
    fn new(json: bool, sub: &'static str) -> Out {
        Out {
            json,
            lines: Vec::new(),
            obj: J::obj(vec![
                ("tool", J::str("a9drv")),
                ("version", J::str(env!("CARGO_PKG_VERSION"))),
                ("subcommand", J::str(sub)),
            ]),
            notes: Vec::new(),
        }
    }

    fn line(&mut self, s: impl Into<String>) {
        self.lines.push(s.into());
    }

    fn blank(&mut self) {
        self.lines.push(String::new());
    }

    fn set(&mut self, k: &str, v: J) {
        self.obj.push(k, v);
    }

    fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }

    fn finish(self, exit: u8, fail: Option<Fail>) -> ExitCode {
        let ok = exit == EXIT_OK && fail.is_none();
        if self.json {
            let mut obj = self.obj;
            obj.push("ok", J::bool(ok));
            obj.push("exit_code", J::num(exit as i64));
            obj.push("notes", J::strings(self.notes.clone()));
            obj.push(
                "error",
                match &fail {
                    None => J::Null,
                    Some(f) => J::obj(vec![
                        ("kind", J::str(f.kind())),
                        ("message", J::str(f.flat())),
                        ("win32", J::opt_num(f.win32().map(|c| c as i64))),
                        ("win32_meaning", J::opt_str(f.win32().map(apply::win32_explain))),
                    ]),
                },
            );
            println!("{}", obj.render());
        } else {
            for l in &self.lines {
                println!("{l}");
            }
            if let Some(f) = &fail {
                eprintln!();
                eprintln!("{}", f.human());
            }
        }
        ExitCode::from(exit)
    }
}

fn node_json(n: &Node) -> J {
    J::obj(vec![
        ("instance_id", J::str(pnp::mask_ecid(&n.instance_id))),
        ("ecid_masked", J::bool(true)),
        ("desc", J::str(&n.device_desc)),
        ("friendly_name", J::opt_str(n.friendly_name.clone())),
        ("class", J::opt_str(n.class_name.clone())),
        ("vid_pid", J::str(format!("{:04X}:{:04X}", n.vid, n.pid))),
        ("location", J::opt_str(n.location.clone())),
        ("parent", J::opt_str(n.parent.clone())),
        ("present", J::bool(n.present)),
        ("problem", J::opt_num(n.problem.map(|p| p as i64))),
        ("service", J::opt_str(n.bound_service().map(|s| s.to_string()))),
        ("service_kind", J::str(n.service_kind().name())),
        ("reset_capable", J::str(n.reset_capability().name())),
        ("checkm8_transport", J::bool(n.service_kind().is_checkm8_transport())),
        ("bound_inf", J::opt_str(n.bound_inf().map(|s| s.to_string()))),
        ("provider", J::opt_str(n.provider.clone())),
        ("driver_version", J::opt_str(n.driver_version.clone())),
        ("hardware_ids", J::strings(n.hardware_ids.clone())),
        ("compatible_ids", J::strings(n.compatible_ids.clone())),
        ("service_sources_disagree", J::bool(n.service_sources_disagree())),
        ("serial", J::opt_str(n.apple_serial().map(pnp::mask_ecid))),
        ("is_interface", J::bool(n.is_interface)),
    ])
}

fn candidate_json(c: &Candidate) -> J {
    J::obj(vec![
        ("inf_file", J::str(&c.inf_file)),
        ("path", J::opt_str(c.path.as_ref().map(|p| p.to_string_lossy().to_string()))),
        ("source", J::str(c.source.name())),
        ("provider", J::str(&c.provider)),
        ("mfg", J::str(&c.mfg)),
        ("description", J::str(&c.description)),
        ("version", J::str(&c.version)),
        ("date", J::str(&c.date)),
        ("section", J::str(&c.section)),
        ("hardware_id", J::str(&c.hardware_id)),
    ])
}

fn human_node(n: &Node) -> Vec<String> {
    let mut v = Vec::new();
    v.push(format!(
        "  {}",
        pnp::mask_ecid(&n.instance_id)
    ));
    v.push(format!("      desc       : {}", n.device_desc));
    if let Some(c) = &n.class_name {
        v.push(format!("      class      : {c}"));
    }
    if let Some(l) = &n.location {
        v.push(format!("      location   : {l}"));
    }
    v.push(format!(
        "      present    : {}{}",
        if n.present { "yes" } else { "NO (remembered node, not in the tree)" },
        match n.present_prop {
            Some(p) if p != n.present => "  (DEVPKEY_Device_IsPresent disagrees - mid-change?)",
            _ => "",
        }
    ));
    if !n.present {
        v.push("      note       : a ghost node from an earlier session; it cannot be bound".to_string());
    }
    if let Some(p) = n.problem {
        v.push(format!("      problem    : {p} (0x{p:X})"));
    }
    let svc = n.bound_service().unwrap_or("(none)");
    v.push(format!(
        "      service    : {svc}{}",
        if n.service_sources_disagree() {
            "  [SPDRP_SERVICE and DEVPKEY_Device_Service disagree]"
        } else {
            ""
        }
    ));
    v.push(format!(
        "      reset      : {}",
        n.service_kind().reset_capability_text()
    ));
    v.push(format!(
        "      bound INF  : {}  {} {}",
        n.bound_inf().unwrap_or("(none)"),
        n.provider.clone().unwrap_or_default(),
        n.driver_version.clone().unwrap_or_default()
    ));
    if let Some(s) = n.apple_serial() {
        v.push(format!("      serial     : {}", pnp::mask_ecid(s)));
    }
    v
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    // A usage failure still has to honour --json, so look for it before parsing.
    let want_json = argv.iter().any(|a| a == "--json");
    let args = match cli::parse(&argv) {
        Ok(a) => a,
        Err(e) => {
            let out = Out::new(want_json, "usage");
            return out.finish(EXIT_USAGE, Some(Fail::Usage(e)));
        }
    };

    match args.sub {
        Sub::Help => {
            println!("{}", cli::help());
            ExitCode::SUCCESS
        }
        Sub::Version => {
            println!("a9drv {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Sub::List => cmd_list(&args),
        Sub::Verify => cmd_verify(&args),
        Sub::Bind => cmd_bind(&args),
        Sub::Restore => cmd_restore(&args),
    }
}

/// Enumerate present Apple devices, plus the remembered ones for diagnostics.
fn survey() -> Result<(Vec<Node>, Vec<Node>), String> {
    let present = pnp::enumerate(Some(pnp::APPLE_VID), false)?;
    let all = pnp::enumerate(Some(pnp::APPLE_VID), true)?;
    Ok((present, all))
}

fn ghosts_for_pid(all: &[Node], pid: u16) -> Vec<String> {
    all.iter()
        .filter(|n| !n.present && n.pid == pid)
        .map(|n| {
            format!(
                "{}  service={}",
                pnp::mask_ecid(&n.instance_id),
                n.bound_service().unwrap_or("(none)")
            )
        })
        .collect()
}

fn select_fail(e: pnp::SelectError, pid: u16, all: &[Node]) -> Fail {
    match e {
        pnp::SelectError::NoneForPid { .. } => Fail::NoDevice {
            pid,
            ghosts: ghosts_for_pid(all, pid),
        },
        pnp::SelectError::NoSuchInstance { instance } => Fail::NotPresent { instance },
        pnp::SelectError::Ambiguous { instances } => Fail::Ambiguous { instances },
    }
}

fn store_scan_lines(out: &mut Out) {
    match store::scan() {
        Ok(packages) => {
            let relevant = store::relevant(&packages);
            out.blank();
            out.line(format!(
                "DRIVER STORE  ({} package(s) in FileRepository; {} relevant to this project)",
                packages.len(),
                relevant.len()
            ));
            let mut arr = Vec::new();
            for p in &relevant {
                let summary = store::read_inf_summary(p, "VID_05AC&PID_1227");
                let role = match store::role(&p.original_inf) {
                    store::PackageRole::LibusbK => "libusbK",
                    store::PackageRole::AppleWinUsb => "Apple/WinUSB",
                    store::PackageRole::Other => "other",
                };
                out.line(format!(
                    "  {:<52} {:<14} {}",
                    p.folder,
                    role,
                    summary
                        .as_ref()
                        .and_then(|s| s.provider.clone())
                        .unwrap_or_else(|| "(provider unreadable)".to_string())
                ));
                if let Some(s) = &summary {
                    if let Some(v) = &s.driver_ver {
                        out.line(format!("      DriverVer : {v}"));
                    }
                    if let Some(c) = &s.catalog {
                        out.line(format!("      catalog   : {c}"));
                    }
                    for m in &s.models {
                        out.line(format!("      model     : {m}"));
                    }
                    for l in &s.license_hints {
                        out.line(format!("      licence   : {l}"));
                    }
                }
                arr.push(J::obj(vec![
                    ("folder", J::str(&p.folder)),
                    ("original_inf", J::str(&p.original_inf)),
                    ("arch", J::str(&p.arch)),
                    ("tag", J::str(&p.tag)),
                    ("role", J::str(role)),
                    (
                        "provider",
                        J::opt_str(summary.as_ref().and_then(|s| s.provider.clone())),
                    ),
                    (
                        "driver_ver",
                        J::opt_str(summary.as_ref().and_then(|s| s.driver_ver.clone())),
                    ),
                    (
                        "catalog",
                        J::opt_str(summary.as_ref().and_then(|s| s.catalog.clone())),
                    ),
                    (
                        "models",
                        J::strings(summary.as_ref().map(|s| s.models.clone()).unwrap_or_default()),
                    ),
                    (
                        "license_hints",
                        J::strings(
                            summary
                                .as_ref()
                                .map(|s| s.license_hints.clone())
                                .unwrap_or_default(),
                        ),
                    ),
                ]));
            }
            out.set("driver_store", J::Arr(arr));
        }
        Err(e) => {
            out.note(format!("driver store not enumerable: {e}"));
            out.set(
                "driver_store",
                J::obj(vec![
                    ("packages", J::Arr(Vec::new())),
                    ("error", J::str(e)),
                ]),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

fn cmd_list(args: &Args) -> ExitCode {
    let mut out = Out::new(args.json, "list");
    out.set("pid_filter", J::opt_num(args.pid.map(|p| p as i64)));
    out.set("include_not_present", J::bool(args.all));

    let nodes = match pnp::enumerate(Some(pnp::APPLE_VID), args.all) {
        Ok(n) => n,
        Err(e) => return out.finish(EXIT_INTERNAL, Some(Fail::Internal(e))),
    };

    if nodes.is_empty() {
        // "No Apple device" and "enumeration is broken" look identical from here.
        // Separating them is the whole point of this check.
        match pnp::enumerate(None, false) {
            Ok(all) if all.is_empty() => {
                return out.finish(
                    EXIT_INTERNAL,
                    Some(Fail::Internal(
                        "SetupAPI enumerated no device nodes at all, so this is a fault in a9drv \
                         rather than an empty bus"
                            .to_string(),
                    )),
                )
            }
            _ => {}
        }
    }

    let filtered: Vec<&Node> = nodes
        .iter()
        .filter(|n| args.pid.map(|p| n.pid == p).unwrap_or(true))
        .collect();

    out.line(format!(
        "a9drv list - {} Apple-VID node(s){}",
        filtered.len(),
        if args.all { ", present and remembered" } else { ", present" }
    ));
    out.blank();

    let present = filtered.iter().filter(|n| n.present).count();
    out.line(format!(
        "  {present} present, {} remembered-but-absent",
        filtered.len() - present
    ));
    out.blank();

    let mut arr = Vec::new();
    // Elevation is reported here as well as in the mutating commands: `list` is
    // the one command that always runs, so it is where the user finds out that
    // the console they are in cannot bind anything.
    let elev = elevate::detect();
    out.set("elevation", J::str(elev.name()));
    out.set("elevated", J::bool(elev.is_elevated()));
    out.set("elevation_detail", elevation_json(elev));
    out.line(format!("  elevation  : {}", elev.name()));
    if let Some(sentence) = elevate::gate(elev) {
        out.line(format!("               bind/restore would refuse: {sentence}"));
    }
    out.blank();

    for n in &filtered {
        for l in human_node(n) {
            out.line(l);
        }
        // For DFU nodes, show what else the store could give this node. That is
        // the evidence the plan is built from.
        let mut cands: Vec<Candidate> = Vec::new();
        if n.is_dfu() {
            match pnp::compatible_drivers(&n.instance_id) {
                Ok(c) => {
                    cands = c;
                    out.line(format!(
                        "      store      : {} compatible package(s) for this node",
                        cands.len()
                    ));
                    for c in &cands {
                        out.line(format!(
                            "        {:<12} {:<22} {:<10} {:<11} {}",
                            c.inf_file, c.provider, c.version, c.date, c.description
                        ));
                    }
                }
                Err(e) => {
                    out.line(format!("      store      : unreadable ({e})"));
                    out.note(format!("compatible-driver list failed for {}: {e}", pnp::mask_ecid(&n.instance_id)));
                }
            }
        }
        out.blank();
        let mut nj = node_json(n);
        nj.push("store_candidates", J::Arr(cands.iter().map(candidate_json).collect()));
        arr.push(nj);
    }

    out.set("nodes", J::Arr(arr));

    if args.pid.is_none() || args.pid == Some(pnp::DFU_PID) {
        store_scan_lines(&mut out);
    }

    if filtered.is_empty() {
        let pid = args.pid_or_default();
        let all = pnp::enumerate(Some(pnp::APPLE_VID), true).unwrap_or_default();
        return out.finish(
            EXIT_NO_DEVICE,
            Some(Fail::NoDevice {
                pid,
                ghosts: ghosts_for_pid(&all, pid),
            }),
        );
    }
    out.finish(EXIT_OK, None)
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

fn cmd_verify(args: &Args) -> ExitCode {
    let mut out = Out::new(args.json, "verify");
    let expect = args.expect_or_default();
    out.set("expect", J::str(match expect {
        Expect::LibusbK => "libusbK",
        Expect::Libusb0 => "libusb0",
        Expect::WinUsb => "winusb",
        Expect::Restored => "restored",
    }));

    let (present, all) = match survey() {
        Ok(v) => v,
        Err(e) => return out.finish(EXIT_INTERNAL, Some(Fail::Internal(e))),
    };
    let pid = args.pid_or_default();
    let node = match pnp::select_node(&present, pid, args.instance.as_deref(), true) {
        Ok(n) => n,
        Err(e) => return out.finish(EXIT_NO_DEVICE, Some(select_fail(e, pid, &all))),
    };

    let state_path = args.state.clone().unwrap_or_else(state::default_path);
    out.set("state_path", J::str(state_path.to_string_lossy().to_string()));
    let record = match state::load(&state_path) {
        Ok(r) => r,
        Err(e) => {
            out.note(format!("rollback file unreadable: {e}"));
            None
        }
    };

    out.set("node", node_json(node));
    out.set("elevated", J::str(elevate::detect().name()));
    out.line(format!("a9drv verify - node {}", pnp::mask_ecid(&node.instance_id)));
    out.blank();
    for l in human_node(node) {
        out.line(l);
    }
    out.blank();

    let outcome = plan::decide_verify(node, expect, record.as_ref());
    out.set(
        "verdict",
        match &outcome {
            VerifyOutcome::Pass { service, wanted, transport } => J::obj(vec![
                ("result", J::str("pass")),
                ("service", J::str(service.clone())),
                ("wanted", J::str(wanted.clone())),
                ("checkm8_transport", J::bool(*transport)),
            ]),
            VerifyOutcome::Fail { service, wanted, detail } => J::obj(vec![
                ("result", J::str("fail")),
                ("service", J::opt_str(service.clone())),
                ("wanted", J::str(wanted.clone())),
                ("detail", J::str(detail.clone())),
            ]),
            VerifyOutcome::CannotVerify { wanted, detail } => J::obj(vec![
                ("result", J::str("cannot_verify")),
                ("wanted", J::str(wanted.clone())),
                ("detail", J::str(detail.clone())),
            ]),
        },
    );

    let (exit, fail) = match &outcome {
        VerifyOutcome::Pass { service, wanted, transport } => {
            out.line(format!(
                "  VERDICT: PASS - service {service} matches {wanted}{}",
                if *transport {
                    "; libusb can reset the port, checkm8 has a transport"
                } else {
                    ""
                }
            ));
            (EXIT_OK, None)
        }
        VerifyOutcome::Fail { service, detail, .. } => (
            EXIT_VERIFY_FAILED,
            Some(Fail::VerifyFailed {
                detail: detail.clone(),
                achieved: service.clone(),
            }),
        ),
        VerifyOutcome::CannotVerify { wanted, detail } => (
            EXIT_STATE,
            Some(Fail::State(format!("cannot verify {wanted}: {detail}"))),
        ),
    };
    out.finish(exit, fail)
}

// ---------------------------------------------------------------------------
// bind / restore shared machinery
// ---------------------------------------------------------------------------

struct Observed {
    service: Option<String>,
    node: Option<Node>,
    attempts: u32,
    waited: Duration,
}

/// Re-read the bound service until it becomes `want` or the timeout expires.
///
/// The driver install restarts the node, so for a moment it is not in the tree at
/// all. A single read after the install would report a false failure.
fn wait_for_service(instance_id: &str, pid: u16, want: &str, timeout: Duration) -> Observed {
    let start = Instant::now();
    let mut attempts = 0u32;
    let mut last: Option<Node> = None;
    loop {
        attempts += 1;
        if let Ok(nodes) = pnp::enumerate(Some(pnp::APPLE_VID), false) {
            if let Some(n) = pnp::find_node(&nodes, instance_id, pid) {
                let svc = n.bound_service().unwrap_or("").to_string();
                if svc.eq_ignore_ascii_case(want) {
                    return Observed {
                        service: Some(svc),
                        node: Some(n.clone()),
                        attempts,
                        waited: start.elapsed(),
                    };
                }
                last = Some(n.clone());
            }
        }
        if start.elapsed() >= timeout {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Observed {
        service: last.as_ref().and_then(|n| n.bound_service().map(|s| s.to_string())),
        node: last,
        attempts,
        waited: start.elapsed(),
    }
}

/// Everything both mutating commands need before they decide anything.
struct Prepared {
    node: Node,
    /// Candidates to select from: published INFs first, then anything Windows'
    /// own list adds.
    candidates: Vec<Candidate>,
    /// Windows' own compatible-driver list, kept separate so the plan can say
    /// whether the chosen package is in it.
    compat: Vec<Candidate>,
    record: Option<state::RollbackRecord>,
    state_path: std::path::PathBuf,
    pid: u16,
    hwid: String,
    /// The package a remembered node from an earlier session is bound to, if
    /// there is one. Evidence about which copy has actually worked on this host.
    known_good: Option<String>,
}

fn prepare(args: &Args, sub: &'static str) -> Result<(Out, Prepared), (Out, Fail)> {
    let mut out = Out::new(args.json, sub);
    let (present, all) = match survey() {
        Ok(v) => v,
        Err(e) => return Err((out, Fail::Internal(e))),
    };
    let pid = args.pid_or_default();
    let node = match pnp::select_node(&present, pid, args.instance.as_deref(), true) {
        Ok(n) => n.clone(),
        Err(e) => return Err((out, select_fail(e, pid, &all))),
    };

    // Windows' own compatible-driver list. Measured on this host to contain only
    // Apple's package for the DFU node, even though two signed libusbK packages
    // are in the store. It is reported, and never used as the only source.
    let compat = match pnp::compatible_drivers(&node.instance_id) {
        Ok(c) => c,
        Err(e) => {
            out.note(format!(
                "Windows' compatible-driver list could not be built for this node: {e}"
            ));
            Vec::new()
        }
    };

    // The published INFs, read from disk. This is where the libusbK package is.
    let marker = format!("VID_{:04X}&PID_{:04X}", node.vid, node.pid);
    let published = match store::scan_published(&marker) {
        Ok(p) => p,
        Err(e) => {
            out.note(format!("published INFs could not be scanned: {e}"));
            Vec::new()
        }
    };
    let mut candidates: Vec<Candidate> = published.iter().map(store::as_candidate).collect();
    for c in &compat {
        if !candidates
            .iter()
            .any(|x| x.inf_file.eq_ignore_ascii_case(&c.inf_file))
        {
            candidates.push(c.clone());
        }
    }
    if candidates.is_empty() {
        out.note(format!(
            "no published INF in {} claims {marker}",
            store::inf_directory().display()
        ));
    }

    let state_path = args.state.clone().unwrap_or_else(state::default_path);
    let record = match state::load(&state_path) {
        Ok(r) => r,
        Err(e) => {
            out.note(format!("rollback file unreadable: {e}"));
            None
        }
    };

    let hwid = args
        .hwid
        .clone()
        .or_else(|| node.hwid_generic())
        .unwrap_or_else(|| format!("USB\\VID_05AC&PID_{:04X}", node.pid));

    let known_good = all
        .iter()
        .filter(|n| !n.present && n.pid == pid)
        .filter_map(|n| n.bound_inf().map(|s| s.to_string()))
        .next();

    let elevated = elevate::detect();
    out.set("pid", J::num(pid as i64));
    out.set("instance", J::str(pnp::mask_ecid(&node.instance_id)));
    out.set("node", node_json(&node));
    out.set("candidates", J::Arr(candidates.iter().map(candidate_json).collect()));
    out.set(
        "windows_compat_list",
        J::Arr(compat.iter().map(candidate_json).collect()),
    );
    out.set("elevation", J::str(elevated.name()));
    out.set("elevated", J::bool(elevated.is_elevated()));
    // The gate's exact sentence is reported in the plan even when dry-running,
    // so it can be read and checked without giving the tool permission to change
    // anything.
    out.set("elevation_detail", elevation_json(elevated));
    out.set("mutates_device_tree", J::bool(args.mutates()));
    out.set("state_path", J::str(state_path.to_string_lossy().to_string()));
    out.set("hwid", J::str(&hwid));
    out.set("known_good_package", J::opt_str(known_good.clone()));
    out.set(
        "rollback_record",
        match &record {
            None => J::Null,
            Some(r) => J::obj(vec![
                ("phase", J::str(format!("{:?}", r.phase).to_lowercase())),
                ("instance_id", J::str(pnp::mask_ecid(&r.instance_id))),
                ("previous_service", J::str(&r.previous_service)),
                ("previous_inf", J::str(&r.previous_inf)),
                ("target_inf", J::str(&r.target_inf)),
                ("saved_unix", J::num(r.saved_unix as i64)),
            ]),
        },
    );

    out.line(format!(
        "a9drv {sub} - node {}",
        pnp::mask_ecid(&node.instance_id)
    ));
    out.blank();
    for l in human_node(&node) {
        out.line(l);
    }
    out.blank();
    let published_only: Vec<&Candidate> = candidates
        .iter()
        .filter(|c| c.source == pnp::CandidateSource::PublishedInf)
        .collect();
    out.line(format!(
        "PACKAGES CLAIMING THIS NODE  ({} published INF(s) in {} whose model lines match {marker})",
        published_only.len(),
        store::inf_directory().display()
    ));
    if published_only.is_empty() {
        out.line("  (none)");
    }
    for c in &published_only {
        out.line(format!(
            "  {:<12} {:<22} {:<10} {:<11} {}",
            c.inf_file, c.provider, c.version, c.date, c.description
        ));
    }
    out.blank();
    out.line("WINDOWS' OWN COMPATIBLE-DRIVER LIST for this node");
    if compat.is_empty() {
        out.line("  (empty)");
    }
    for c in &compat {
        out.line(format!(
            "  {:<12} {:<22} {:<10} {:<11} {}",
            c.inf_file, c.provider, c.version, c.date, c.description
        ));
    }
    out.blank();

    Ok((
        out,
        Prepared {
            node,
            candidates,
            compat,
            record,
            state_path,
            pid,
            hwid,
            known_good,
        },
    ))
}

fn elevation_json(e: elevate::Elevation) -> J {
    J::obj(vec![
        ("state", J::str(e.name())),
        ("elevated", J::bool(e.is_elevated())),
        (
            "action",
            J::opt_str(elevate::gate(e)),
        ),
    ])
}

// ---------------------------------------------------------------------------
// bind
// ---------------------------------------------------------------------------

fn cmd_bind(args: &Args) -> ExitCode {
    let (mut out, prep) = match prepare(args, "bind") {
        Ok(v) => v,
        Err((out, fail)) => return out.finish(fail.exit_code(), Some(fail)),
    };
    let Prepared { node, candidates, compat, record: _, state_path, pid, hwid, known_good } = prep;

    let action = plan::decide_bind(&node, &candidates, args.prefer, args.inf.as_deref());
    let target = args.prefer.target_service().to_string();
    // How many present devices a hardware-ID-scoped operation would touch. Stated
    // in the plan, not discovered afterwards.
    let present_now = pnp::enumerate(Some(pnp::APPLE_VID), false).unwrap_or_default();
    let affected = pnp::count_present_with_hwid(&present_now, &hwid);

    // ---- state what will happen, before anything happens ----
    // The INF path the forced-update method will use, resolved while planning so
    // that the plan states it and the apply step cannot disagree with the plan.
    let mut plan_inf_path: Option<std::path::PathBuf> = None;
    match &action {
        BindAction::AlreadyBound { service } => {
            out.line(format!(
                "PLAN\n  action     : nothing to do - this node is already bound to {service}\n  \
                 the requested family is already in place, so a second run changes nothing"
            ));
            out.set(
                "plan",
                J::obj(vec![
                    ("action", J::str("already_bound")),
                    ("service", J::str(service.clone())),
                    ("applied", J::bool(false)),
                ]),
            );
            out.set("result", J::obj(vec![("applied", J::bool(false))]));
            out.line("");
            out.line(format!(
                "RESULT: already bound to {service}. Nothing was changed, and no elevation was needed."
            ));
            return out.finish(EXIT_OK, None);
        }
        BindAction::NoMatchingPackage { detail } => {
            out.line(format!("PLAN\n  action     : cannot bind\n  reason     : {detail}"));
            out.set(
                "plan",
                J::obj(vec![
                    ("action", J::str("no_matching_package")),
                    ("detail", J::str(detail.clone())),
                ]),
            );
            return out.finish(EXIT_NO_PACKAGE, Some(Fail::NoPackage { detail: detail.clone() }));
        }
        BindAction::Select { inf_file, provider, version, target_service, alternatives } => {
            if args.method == Method::UpdateDriverForPnp {
                plan_inf_path =
                    apply::resolve_target_inf(inf_file, args.inf.as_deref(), &candidates);
            }
            let chosen_in_compat = compat
                .iter()
                .any(|c| c.inf_file.eq_ignore_ascii_case(inf_file));
            out.line("PLAN");
            out.line(format!(
                "  action     : bind this node to the driver-store package {inf_file} ({provider} {version})"
            ));
            out.line(format!("  target     : driver service {target_service}, which can reset the port"));
            out.line(format!("  method     : {}", args.method.label()));
            out.line(format!(
                "  inf path   : {}",
                plan_inf_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| {
                        if args.method == Method::UpdateDriverForPnp {
                            "NOT FOUND - this run would stop before touching the device".to_string()
                        } else {
                            "(not needed: the package is selected by store identity)".to_string()
                        }
                    })
            ));
            out.line(format!(
                "  hwid       : {hwid}   ({affected} present device(s) carry this hardware ID)"
            ));
            if !alternatives.is_empty() {
                out.line(format!(
                    "  also there : {} (same package, not chosen: lowest published name wins)",
                    alternatives.join(", ")
                ));
            }
            if !chosen_in_compat {
                out.line(
                    "  note       : this package is NOT in Windows' own compatible-driver list for",
                );
                out.line(
                    "               this node, so the INF path is forced explicitly. That is the step",
                );
                out.line(
                    "               Zadig performs too; measured here: that list offers only Apple's package.",
                );
            }
            if let Some(kg) = &known_good {
                if !kg.eq_ignore_ascii_case(inf_file) {
                    out.line(format!(
                        "  note       : a remembered node from an earlier session is bound to {kg};"
                    ));
                    out.line(format!(
                        "               if {inf_file} is refused, `--inf {kg}` is the copy known to have bound here."
                    ));
                }
            }
            out.line("  will       : select the driver for this node and restart it");
            out.line("  will not   : install, copy or delete any driver package; touch any other device");
            out.line(format!("  rollback   : {}", state_path.display()));
            out.line(format!("  elevation  : {}", elevate::detect().name()));
            out.set(
                "plan",
                J::obj(vec![
                    ("action", J::str("select_package")),
                    ("inf_file", J::str(inf_file.clone())),
                    (
                        "inf_path",
                        J::opt_str(
                            plan_inf_path
                                .as_ref()
                                .map(|p| p.to_string_lossy().to_string()),
                        ),
                    ),
                    ("provider", J::str(provider.clone())),
                    ("version", J::str(version.clone())),
                    ("target_service", J::str(target_service.clone())),
                    ("method", J::str(args.method.name())),
                    ("hwid", J::str(hwid.clone())),
                    ("chosen_in_windows_compat_list", J::bool(chosen_in_compat)),
                    ("affected_present_devices", J::num(affected as i64)),
                    ("alternatives", J::strings(alternatives.clone())),
                    ("known_good_package", J::opt_str(known_good.clone())),
                    ("selection_source", J::str(
                        candidates
                            .iter()
                            .find(|c| c.inf_file.eq_ignore_ascii_case(inf_file))
                            .map(|c| c.source.name())
                            .unwrap_or("explicit"),
                    )),
                    ("will", J::strings([
                        "select the driver package for this device node",
                        "restart the node so the new driver binds",
                        "record the previous binding for restore",
                    ])),
                    ("will_not", J::strings([
                        "install, copy, import or delete any driver package",
                        "touch any other device",
                        "modify the device firmware in any way",
                    ])),
                ]),
            );
        }
    }

    if args.dry_run {
        out.set("result", J::obj(vec![("applied", J::bool(false)), ("dry_run", J::bool(true))]));
        out.line("");
        out.line("DRY RUN: nothing was changed.");
        return out.finish(EXIT_OK, None);
    }

    // ---- elevation, before anything is touched ----
    let elevation = elevate::detect();
    out.set("elevation_detail", elevation_json(elevation));
    if let Some(sentence) = elevate::gate(elevation) {
        return out.finish(
            EXIT_NEEDS_ELEVATION,
            Some(Fail::Elevation(sentence)),
        );
    }

    let inf_file = match &action {
        BindAction::Select { inf_file, .. } => inf_file.clone(),
        _ => unreachable!("handled above"),
    };

    // ---- record the rollback before changing anything ----
    let mut rec = state::RollbackRecord::from_node(&node, &inf_file, &target);
    if let Err(e) = state::save(&state_path, &rec) {
        return out.finish(
            EXIT_STATE,
            Some(Fail::State(format!(
                "{e}\n  nothing was changed: the rollback record is written before the driver API \
                 is called, on purpose"
            ))),
        );
    }

    // ---- do it ----
    //
    // The default method needs an INF path on disk; the package was chosen from
    // the published INFs, so the path is known rather than guessed. Resolution
    // resolves in order: an explicit --inf path, the candidate's own path, the
    // published location, the staged store copy.
    let outcome = match args.method {
        Method::UpdateDriverForPnp => match plan_inf_path {
            None => {
                return out.finish(
                    EXIT_NO_PACKAGE,
                    Some(Fail::NoPackage {
                        detail: format!(
                            "{inf_file} could not be found on disk - neither at {} nor as a staged \
                             copy in the driver store - so there is nothing to force",
                            apply::inf_path_for(&inf_file).display()
                        ),
                    }),
                )
            }
            Some(path) => apply::update_for_pnp(&hwid, &path),
        },
        Method::DriverStore => match apply::install_from_store(&node.instance_id, &inf_file) {
            Ok(o) => o,
            Err(e) => {
                let observed =
                    wait_for_service(&node.instance_id, pid, &target, Duration::from_secs(2));
                return out.finish(
                    EXIT_BIND_REFUSED,
                    Some(Fail::Refused {
                        method: args.method,
                        win32: 0,
                        detail: e,
                        achieved: observed.service,
                    }),
                );
            }
        },
    };

    out.set(
        "apply",
        J::obj(vec![
            ("method", J::str(outcome.method.name())),
            ("api_ok", J::bool(outcome.ok)),
            ("win32", J::num(outcome.win32 as i64)),
            (
                "win32_meaning",
                J::opt_str((outcome.win32 != 0).then(|| apply::win32_explain(outcome.win32).to_string())),
            ),
            ("reboot_required", J::bool(outcome.reboot_required)),
            ("early_error", J::opt_str(outcome.early_error.clone())),
        ]),
    );

    // ---- prove it, by re-reading the bound service ----
    let observed = wait_for_service(&node.instance_id, pid, &target, VERIFY_TIMEOUT);
    out.set(
        "verify",
        J::obj(vec![
            ("target_service", J::str(target.clone())),
            ("observed_service", J::opt_str(observed.service.clone())),
            ("attempts", J::num(observed.attempts as i64)),
            ("waited_ms", J::num(observed.waited.as_millis() as i64)),
        ]),
    );
    if let Some(n) = &observed.node {
        out.set("node_after", node_json(n));
    }

    let achieved = observed.service.clone();
    let reached = achieved
        .as_deref()
        .map(|s| s.eq_ignore_ascii_case(&target))
        .unwrap_or(false);

    if !reached {
        // Fail loudly. This is the case the whole tool exists to prevent.
        let (exit, fail) = if classify::is_still_winusb(achieved.as_deref()) {
            (
                if outcome.ok { EXIT_VERIFY_FAILED } else { EXIT_BIND_REFUSED },
                Fail::StillWinUsb {
                    method: outcome.method,
                    win32: outcome.win32,
                    api_ok: outcome.ok,
                    achieved,
                },
            )
        } else if outcome.ok {
            (
                EXIT_VERIFY_FAILED,
                Fail::VerifyFailed {
                    detail: format!(
                        "the driver API reported success but the node is bound to {:?}, not {target}",
                        achieved.clone().unwrap_or_default()
                    ),
                    achieved,
                },
            )
        } else {
            (
                EXIT_BIND_REFUSED,
                Fail::Refused {
                    method: outcome.method,
                    win32: outcome.win32,
                    detail: outcome.explanation(),
                    achieved,
                },
            )
        };
        return out.finish(exit, Some(fail));
    }

    // ---- verified: update the record and report ----
    rec.phase = state::Phase::Bound;
    if let Err(e) = state::save(&state_path, &rec) {
        out.note(format!("bound, but the rollback record could not be updated: {e}"));
    }

    out.set("result", J::obj(vec![
        ("applied", J::bool(true)),
        ("method", J::str(outcome.method.name())),
        ("reboot_required", J::bool(outcome.reboot_required)),
        ("service", J::opt_str(achieved.clone())),
        ("checkm8_transport", J::bool(true)),
    ]));
    out.line("");
    out.line("RESULT: VERIFIED");
    out.line(format!(
        "  service    : {}{}",
        achieved.clone().unwrap_or_default(),
        if outcome.reboot_required { "   (a reboot was requested by the driver API)" } else { "" }
    ));
    out.line("  reset      : YES - this driver performs a real host-initiated port reset");
    out.line(format!(
        "  rollback   : a9drv restore   (previous binding: {} via {})",
        rec.previous_service,
        if rec.previous_inf.is_empty() {
            "(unknown)"
        } else {
            rec.previous_inf.as_str()
        }
    ));
    out.line("  next       : a9ctl --dfu     (confirm the transport), then run the exploit");
    out.finish(EXIT_OK, None)
}

// ---------------------------------------------------------------------------
// restore
// ---------------------------------------------------------------------------

fn cmd_restore(args: &Args) -> ExitCode {
    let (mut out, prep) = match prepare(args, "restore") {
        Ok(v) => v,
        Err((out, fail)) => return out.finish(fail.exit_code(), Some(fail)),
    };
    let Prepared { node, candidates, compat: _, record, state_path, pid, hwid, known_good: _ } = prep;

    let action = plan::decide_restore(&node, &candidates, record.as_ref(), args.inf.as_deref());

    // Resolved while planning, so the plan states the exact INF that will be
    // forced and the apply step cannot disagree with it.
    let mut plan_inf_path: Option<std::path::PathBuf> = None;
    match &action {
        RestoreAction::NothingToRestore { service } => {
            out.line(format!(
                "PLAN\n  action     : nothing to restore - this node is bound to {service}, which is \
                 not a libusb-family driver"
            ));
            out.set(
                "plan",
                J::obj(vec![
                    ("action", J::str("nothing_to_restore")),
                    ("service", J::str(service.clone())),
                ]),
            );
            out.line("");
            out.line("RESULT: nothing to do. Nothing was changed.");
            return out.finish(EXIT_OK, None);
        }
        RestoreAction::NoSource { detail } => {
            out.line(format!("PLAN\n  action     : cannot restore\n  reason     : {detail}"));
            out.set(
                "plan",
                J::obj(vec![
                    ("action", J::str("no_restore_source")),
                    ("detail", J::str(detail.clone())),
                ]),
            );
            return out.finish(EXIT_NO_PACKAGE, Some(Fail::NoPackage { detail: detail.clone() }));
        }
        RestoreAction::Select { inf_file, provider, version, source, target_service } => {
            let source_text = match source {
                RestoreSource::Record { .. } => "the rollback record".to_string(),
                RestoreSource::DriverStore => {
                    "the driver store (no usable rollback record: Apple's package was found by provider)"
                        .to_string()
                }
                RestoreSource::Explicit => "--inf".to_string(),
            };
            out.line("PLAN");
            if args.method == Method::UpdateDriverForPnp {
                plan_inf_path =
                    apply::resolve_target_inf(inf_file, args.inf.as_deref(), &candidates);
            }
            out.line(format!(
                "  action     : rebind this node to {inf_file} ({provider} {version})"
            ));
            out.line(format!("  restoring  : {target_service}{}",
                if target_service.is_empty() { String::new() } else { " (the service recorded before the bind)".to_string() }));
            out.line(format!("  source     : {source_text}"));
            out.line(format!("  method     : {}", args.method.label()));
            out.line(format!(
                "  inf path   : {}",
                plan_inf_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| {
                        if args.method == Method::UpdateDriverForPnp {
                            "NOT FOUND - this run would stop before touching the device".to_string()
                        } else {
                            "(not needed: the package is selected by store identity)".to_string()
                        }
                    })
            ));
            out.line(format!("  hwid       : {hwid}"));
            out.line("  will       : select the driver for this node and restart it");
            out.line("  will not   : install, copy or delete any driver package; touch any other device");
            out.line(format!("  elevation  : {}", elevate::detect().name()));
            out.set(
                "plan",
                J::obj(vec![
                    ("action", J::str("restore_package")),
                    ("inf_file", J::str(inf_file.clone())),
                    (
                        "inf_path",
                        J::opt_str(
                            plan_inf_path
                                .as_ref()
                                .map(|p| p.to_string_lossy().to_string()),
                        ),
                    ),
                    ("provider", J::str(provider.clone())),
                    ("version", J::str(version.clone())),
                    ("target_service", J::str(target_service.clone())),
                    ("method", J::str(args.method.name())),
                    ("hwid", J::str(hwid.clone())),
                    ("source", J::str(source_text)),
                ]),
            );
        }
    }

    if args.dry_run {
        out.set("result", J::obj(vec![("applied", J::bool(false)), ("dry_run", J::bool(true))]));
        out.line("");
        out.line("DRY RUN: nothing was changed.");
        return out.finish(EXIT_OK, None);
    }

    let elevation = elevate::detect();
    out.set("elevation_detail", elevation_json(elevation));
    if let Some(sentence) = elevate::gate(elevation) {
        return out.finish(EXIT_NEEDS_ELEVATION, Some(Fail::Elevation(sentence)));
    }

    let (inf_file, target_service) = match &action {
        RestoreAction::Select { inf_file, target_service, .. } => {
            (inf_file.clone(), target_service.clone())
        }
        _ => unreachable!("handled above"),
    };

    let outcome = match args.method {
        Method::UpdateDriverForPnp => match plan_inf_path {
            None => {
                return out.finish(
                    EXIT_NO_PACKAGE,
                    Some(Fail::NoPackage {
                        detail: format!(
                            "{inf_file} could not be found on disk - neither at {} nor as a staged \
                             copy in the driver store",
                            apply::inf_path_for(&inf_file).display()
                        ),
                    }),
                )
            }
            Some(path) => apply::update_for_pnp(&hwid, &path),
        },
        Method::DriverStore => match apply::install_from_store(&node.instance_id, &inf_file) {
            Ok(o) => o,
            Err(e) => {
                // The per-node path needs the package to be in the node's
                // compatible-driver list, which on this host does not contain it.
                // Fall back to the path-based API rather than giving up.
                match apply::resolve_target_inf(&inf_file, args.inf.as_deref(), &candidates) {
                    Some(path) => {
                        out.note(format!(
                            "DiInstallDevice path failed ({e}); fell back to {hwid} + {}",
                            path.display()
                        ));
                        apply::update_for_pnp(&hwid, &path)
                    }
                    None => {
                        let observed = wait_for_service(
                            &node.instance_id,
                            pid,
                            &target_service,
                            Duration::from_secs(2),
                        );
                        return out.finish(
                            EXIT_BIND_REFUSED,
                            Some(Fail::Refused {
                                method: args.method,
                                win32: 0,
                                detail: format!("{e}; and the INF could not be found on disk either"),
                                achieved: observed.service,
                            }),
                        );
                    }
                }
            }
        },
    };

    out.set(
        "apply",
        J::obj(vec![
            ("method", J::str(outcome.method.name())),
            ("api_ok", J::bool(outcome.ok)),
            ("win32", J::num(outcome.win32 as i64)),
            ("reboot_required", J::bool(outcome.reboot_required)),
            ("early_error", J::opt_str(outcome.early_error.clone())),
        ]),
    );

    // Verification for restore is the inverse of bind: the service must NOT be
    // reset-capable any more. Waiting on an exact service name is not possible
    // when there was no record, so poll until it stops being libusb-family.
    let deadline = Instant::now() + VERIFY_TIMEOUT;
    let mut observed_service = node.bound_service().map(|s| s.to_string());
    let mut attempts = 0u32;
    let mut node_after: Option<Node> = None;
    loop {
        attempts += 1;
        if let Ok(nodes) = pnp::enumerate(Some(pnp::APPLE_VID), false) {
            if let Some(n) = pnp::find_node(&nodes, &node.instance_id, pid) {
                let svc = n.bound_service().unwrap_or("").to_string();
                observed_service = Some(svc.clone());
                node_after = Some(n.clone());
                let done = if target_service.is_empty() {
                    !classify::ServiceKind::parse(&svc).is_checkm8_transport()
                } else {
                    svc.eq_ignore_ascii_case(&target_service)
                };
                if done {
                    break;
                }
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    out.set(
        "verify",
        J::obj(vec![
            ("target_service", J::str(if target_service.is_empty() { "(anything not libusb-family)".to_string() } else { target_service.clone() })),
            ("observed_service", J::opt_str(observed_service.clone())),
            ("attempts", J::num(attempts as i64)),
        ]),
    );
    if let Some(n) = &node_after {
        out.set("node_after", node_json(n));
    }

    let achieved = observed_service.clone();
    let restored = match achieved.as_deref() {
        None => false,
        Some(s) => {
            if target_service.is_empty() {
                !classify::ServiceKind::parse(s).is_checkm8_transport()
            } else {
                s.eq_ignore_ascii_case(&target_service)
            }
        }
    };

    if !restored {
        let (exit, fail) = if outcome.ok {
            (
                EXIT_VERIFY_FAILED,
                Fail::VerifyFailed {
                    detail: format!(
                        "the driver API reported success but the node is bound to {:?}, not {:?}",
                        achieved.clone().unwrap_or_default(),
                        target_service
                    ),
                    achieved,
                },
            )
        } else {
            (
                EXIT_BIND_REFUSED,
                Fail::Refused {
                    method: outcome.method,
                    win32: outcome.win32,
                    detail: outcome.explanation(),
                    achieved,
                },
            )
        };
        return out.finish(exit, Some(fail));
    }

    if let Some(mut r) = record {
        if r.instance_id.eq_ignore_ascii_case(&node.instance_id) {
            r.phase = state::Phase::Restored;
            r.saved_unix = state::now_unix();
            if let Err(e) = state::save(&state_path, &r) {
                out.note(format!("restored, but the rollback record could not be updated: {e}"));
            }
        }
    }

    out.set("result", J::obj(vec![
        ("applied", J::bool(true)),
        ("method", J::str(outcome.method.name())),
        ("service", J::opt_str(achieved.clone())),
        ("checkm8_transport", J::bool(false)),
    ]));
    out.line("");
    out.line("RESULT: VERIFIED");
    out.line(format!(
        "  service    : {}  (checkm8 can no longer run until you bind again, which is the point)",
        achieved.clone().unwrap_or_default()
    ));
    out.line("  next       : a9drv verify --expect winusb");
    out.finish(EXIT_OK, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_failure_has_a_distinct_kind_and_a_documented_exit_code() {
        let cases: Vec<(Fail, u8, &str)> = vec![
            (Fail::Elevation("x"), EXIT_NEEDS_ELEVATION, "needs_elevation"),
            (Fail::NoDevice { pid: 0x1227, ghosts: vec![] }, EXIT_NO_DEVICE, "no_device"),
            (Fail::NotPresent { instance: "x".into() }, EXIT_NO_DEVICE, "not_present"),
            (Fail::Ambiguous { instances: vec![] }, EXIT_NO_DEVICE, "ambiguous_device"),
            (Fail::NoPackage { detail: "x".into() }, EXIT_NO_PACKAGE, "no_matching_package"),
            (
                Fail::Refused { method: Method::DriverStore, win32: 5, detail: "x".into(), achieved: None },
                EXIT_BIND_REFUSED,
                "binding_refused",
            ),
            (
                Fail::StillWinUsb { method: Method::DriverStore, win32: 0, api_ok: true, achieved: Some("WINUSB".into()) },
                EXIT_VERIFY_FAILED,
                "still_winusb",
            ),
            (
                Fail::StillWinUsb { method: Method::DriverStore, win32: 5, api_ok: false, achieved: Some("WINUSB".into()) },
                EXIT_BIND_REFUSED,
                "still_winusb",
            ),
            (Fail::VerifyFailed { detail: "x".into(), achieved: None }, EXIT_VERIFY_FAILED, "verify_failed"),
            (Fail::State("x".into()), EXIT_STATE, "state_file"),
            (Fail::Internal("x".into()), EXIT_INTERNAL, "internal"),
            (Fail::Usage("x".into()), EXIT_USAGE, "usage"),
        ];
        for (f, code, kind) in cases {
            assert_eq!(f.exit_code(), code, "{kind}");
            assert_eq!(f.kind(), kind);
            assert!(!f.human().is_empty(), "{kind} must print something");
            assert!(!f.flat().is_empty(), "{kind} must have a one-line form");
        }
    }

    #[test]
    fn the_still_winusb_failure_is_loud_and_actionable() {
        let f = Fail::StillWinUsb {
            method: Method::DriverStore,
            win32: 5,
            api_ok: false,
            achieved: Some("WINUSB".to_string()),
        };
        let text = f.human();
        assert!(text.contains("STILL BOUND TO WINUSB"));
        assert!(text.contains("CANNOT run"));
        assert!(text.contains("windows_winusb.c:3412-3419"));
        // It must name both the retry and the escape hatch.
        assert!(text.contains("--method update"));
        assert!(text.contains("a9drv restore"));
        // And it must not pretend the API error is the whole story.
        assert!(text.contains("Win32 5"));
    }

    #[test]
    fn the_no_package_failure_says_it_is_not_a_refusal() {
        let f = Fail::NoPackage { detail: "nothing matched".to_string() };
        let text = f.human();
        assert!(text.contains("NOT a refusal"), "{text}");
        let g = Fail::Refused {
            method: Method::UpdateDriverForPnp,
            win32: 5,
            detail: "denied".to_string(),
            achieved: Some("WINUSB".to_string()),
        };
        let gtext = g.human();
        assert!(gtext.contains("refusal rather than a missing package"), "{gtext}");
        assert!(gtext.contains("a9drv bind --method di"), "{gtext}");
    }

    #[test]
    fn no_device_reports_ghosts_without_pretending_they_are_usable() {
        let f = Fail::NoDevice {
            pid: 0x1227,
            ghosts: vec!["USB\\VID_05AC&PID_1227\\CPID:8000  service=libusbK".to_string()],
        };
        let text = f.human();
        assert!(text.contains("ghost"));
        assert!(text.contains("cannot be bound"));
    }

    #[test]
    fn elevation_message_is_printed_verbatim_with_one_full_stop() {
        let f = Fail::Elevation(elevate::NOT_ELEVATED_ACTION);
        let text = f.human();
        assert!(text.ends_with('.'));
        assert_eq!(text.matches('.').count(), 1);
        assert!(!text.contains("0x"));
    }
}
