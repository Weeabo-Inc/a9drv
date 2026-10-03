//! Argument parsing. Hand-rolled so the accepted grammar is exactly the one in
//! `--help`, and so every rule below is covered by a unit test rather than by a
//! parser crate's opinion.

use std::path::PathBuf;

use crate::apply::Method;
use crate::plan::{Expect, Preference};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sub {
    List,
    Bind,
    Verify,
    Restore,
    Help,
    Version,
}

impl Sub {
    pub fn parse(s: &str) -> Option<Sub> {
        match s.to_ascii_lowercase().as_str() {
            "list" | "ls" => Some(Sub::List),
            "bind" => Some(Sub::Bind),
            "verify" => Some(Sub::Verify),
            "restore" => Some(Sub::Restore),
            "help" => Some(Sub::Help),
            "version" => Some(Sub::Version),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Sub::List => "list",
            Sub::Bind => "bind",
            Sub::Verify => "verify",
            Sub::Restore => "restore",
            Sub::Help => "help",
            Sub::Version => "version",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub sub: Sub,
    /// `None` means "every Apple-VID node" for `list`, and the DFU PID for the
    /// other subcommands.
    pub pid: Option<u16>,
    pub instance: Option<String>,
    pub prefer: Preference,
    pub expect: Option<Expect>,
    pub inf: Option<String>,
    pub hwid: Option<String>,
    pub method: Method,
    pub state: Option<PathBuf>,
    pub json: bool,
    pub dry_run: bool,
    pub all: bool,
}

impl Default for Args {
    fn default() -> Args {
        Args {
            sub: Sub::List,
            pid: None,
            instance: None,
            prefer: Preference::LibusbK,
            expect: None,
            inf: None,
            hwid: None,
            method: Method::default(),
            state: None,
            json: false,
            dry_run: false,
            all: false,
        }
    }
}

impl Args {
    /// The PID a command acts on: what was asked for, else the DFU PID.
    pub fn pid_or_default(&self) -> u16 {
        self.pid.unwrap_or(crate::pnp::DFU_PID)
    }

    /// The expectation for `verify`, defaulting to the thing we actually need.
    pub fn expect_or_default(&self) -> Expect {
        self.expect.unwrap_or(Expect::LibusbK)
    }

    pub fn mutates(&self) -> bool {
        matches!(self.sub, Sub::Bind | Sub::Restore)
    }
}

fn need_value(argv: &[String], i: usize, flag: &str) -> Result<String, String> {
    argv.get(i + 1)
        .filter(|v| !v.starts_with("--"))
        .cloned()
        .ok_or_else(|| format!("{flag} needs a value; see a9drv --help"))
}

/// Parse `--pid`. PIDs are hexadecimal, with or without a `0x` prefix: the DFU
/// node is `PID_1227`, and that is how everyone refers to it.
fn parse_pid(v: &str) -> Result<u16, String> {
    let trimmed = v.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u16::from_str_radix(hex, 16).map_err(|_| {
        format!("--pid {v:?} is not a hexadecimal USB product ID (try --pid 1227)")
    })
}

pub fn parse(argv: &[String]) -> Result<Args, String> {
    // Help and version are answered before anything else is looked at: a user
    // asking "what does this do" must not be stopped by a typo elsewhere on the
    // line.
    if argv.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(Args {
            sub: Sub::Help,
            ..Default::default()
        });
    }
    if argv.iter().any(|a| a == "--version" || a == "-V") {
        return Ok(Args {
            sub: Sub::Version,
            ..Default::default()
        });
    }

    let mut args = Args::default();
    let mut sub: Option<Sub> = None;
    let mut i = 0;

    while i < argv.len() {
        let a = argv[i].as_str();
        match a {
            "--json" => args.json = true,
            "--dry-run" | "-n" => args.dry_run = true,
            "--all" | "-a" => args.all = true,
            "--pid" => {
                let v = need_value(argv, i, "--pid")?;
                args.pid = Some(parse_pid(&v)?);
                i += 1;
            }
            "--instance" | "--id" => {
                args.instance = Some(need_value(argv, i, "--instance")?);
                i += 1;
            }
            "--prefer" => {
                let v = need_value(argv, i, "--prefer")?;
                args.prefer = Preference::parse(&v).ok_or_else(|| {
                    format!("--prefer {v:?} is not a driver family (libusbK, libusb0)")
                })?;
                i += 1;
            }
            "--expect" => {
                let v = need_value(argv, i, "--expect")?;
                args.expect = Some(Expect::parse(&v).ok_or_else(|| {
                    format!("--expect {v:?} is not one of: libusbK, libusb0, winusb, restored")
                })?);
                i += 1;
            }
            "--inf" => {
                args.inf = Some(need_value(argv, i, "--inf")?);
                i += 1;
            }
            "--hwid" => {
                args.hwid = Some(need_value(argv, i, "--hwid")?);
                i += 1;
            }
            "--method" => {
                let v = need_value(argv, i, "--method")?;
                args.method = Method::parse(&v)
                    .ok_or_else(|| format!("--method {v:?} is not one of: di, update"))?;
                i += 1;
            }
            "--state" => {
                args.state = Some(PathBuf::from(need_value(argv, i, "--state")?));
                i += 1;
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option {other:?}; see a9drv --help"));
            }
            other => {
                if sub.is_some() {
                    return Err(format!(
                        "unexpected extra argument {other:?} (subcommand already given); see a9drv --help"
                    ));
                }
                sub = Some(Sub::parse(other).ok_or_else(|| {
                    format!("unknown subcommand {other:?}; expected list, bind, verify, restore")
                })?);
            }
        }
        i += 1;
    }

    args.sub = sub.ok_or_else(|| {
        "no subcommand given; expected list, bind, verify or restore (see a9drv --help)".to_string()
    })?;

    // Per-subcommand option validation. Being strict here means a mistyped flag
    // is a usage error instead of a silently ignored intention.
    let reject = |present: bool, flag: &str, allowed: &[Sub]| -> Result<(), String> {
        if present && !allowed.contains(&args.sub) {
            let names: Vec<&str> = allowed.iter().map(|s| s.name()).collect();
            return Err(format!(
                "{flag} is only valid for: {}",
                names.join(", ")
            ));
        }
        Ok(())
    };
    reject(args.inf.is_some(), "--inf", &[Sub::Bind, Sub::Restore])?;
    reject(args.hwid.is_some(), "--hwid", &[Sub::Bind, Sub::Restore])?;
    reject(args.expect.is_some(), "--expect", &[Sub::Verify])?;
    reject(args.all, "--all", &[Sub::List])?;
    reject(
        args.prefer != Preference::LibusbK,
        "--prefer",
        &[Sub::Bind],
    )?;
    reject(args.method != Method::default(), "--method", &[Sub::Bind, Sub::Restore])?;

    Ok(args)
}

pub fn help() -> String {
    format!(
        "\
a9drv {version} - bind the Apple A9 DFU node to libusbK, verify it, restore it

USAGE
  a9drv <subcommand> [options]

SUBCOMMANDS
  list      every Apple-VID (05AC) device node: bound INF, provider, version,
            driver service and whether that service can reset the port.
            For DFU nodes it also lists the packages already in the driver
            store that could be bound.
  bind      force an already-present driver-store package onto the DFU node so
            that libusb can perform the host-initiated port reset checkm8 needs.
  verify    re-read the bound driver service and check it against an
            expectation. Read-only; needs no elevation.
  restore   put the previous binding back, using the recorded rollback file or,
            failing that, Apple's own package from the driver store.

OPTIONS
  --pid <hex>        USB product ID to act on (default: 1227, DFU). For `list`,
                     omitting it lists every Apple-VID node.
  --instance <id>    exact device instance ID, when more than one node shares
                     the PID.
  --prefer <family>  bind only: libusbK (default) or libusb0.
  --expect <what>    verify only: libusbK (default), libusb0, winusb, restored.
  --inf <name|path>  bind/restore: force this package instead of choosing one
                     (an `oemNN.inf` published name, or a full path).
  --hwid <id>        bind/restore: hardware ID for the --method update path
                     (default: the node's ID without its &REV_ qualifier).
  --method <m>       bind/restore: update (default - explicit INF path plus a
                     hardware ID with INSTALLFLAG_FORCE) or di (DiInstallDevice,
                     one device node, needs the package in Windows' own
                     compatible-driver list).
  --state <path>     rollback file (default: %ProgramData%\\a9drv\\last-bind.conf).
  --dry-run          print the plan and change nothing.
  --json             print one JSON object instead of human text.
  --all              list: include nodes Windows remembers but that are not
                     present (ghosts from earlier sessions).
  -h, --help         this text.
  -V, --version      version.

EXIT CODES
  0 ok                          5 the driver API refused (package present)
  1 internal error              6 no matching package in the driver store
  2 verification failed         7 usage error
  3 needs elevation             8 rollback file problem
  4 no target device node

NOTES
  * `bind` and `restore` need an elevated console. a9drv never self-elevates.
  * Nothing here installs or ships a driver: the signed libusbK package must
    already be in the driver store. a9drv only selects it for this node.
",
        version = env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Args, String> {
        let argv: Vec<String> = s.split_whitespace().map(|x| x.to_string()).collect();
        parse(&argv)
    }

    #[test]
    fn parses_the_command_line_from_the_task() {
        let a = p("bind --pid 1227 --prefer libusbK").unwrap();
        assert_eq!(a.sub, Sub::Bind);
        assert_eq!(a.pid, Some(0x1227));
        assert_eq!(a.prefer, Preference::LibusbK);
        assert!(!a.json);
        assert!(!a.dry_run);
        assert!(a.mutates());
    }

    #[test]
    fn pid_is_hexadecimal_with_or_without_prefix() {
        assert_eq!(p("bind --pid 1227").unwrap().pid, Some(0x1227));
        assert_eq!(p("bind --pid 0x1227").unwrap().pid, Some(0x1227));
        assert_eq!(p("bind --pid 12A8").unwrap().pid, Some(0x12A8));
        assert!(p("bind --pid zzz").unwrap_err().contains("hexadecimal"));
        assert!(p("bind --pid").unwrap_err().contains("needs a value"));
    }

    #[test]
    fn subcommand_may_come_before_or_after_the_flags() {
        let a = p("--json --dry-run list --all").unwrap();
        assert_eq!(a.sub, Sub::List);
        assert!(a.json && a.dry_run && a.all);
        let b = p("list --all --json --dry-run").unwrap();
        assert_eq!(b.sub, Sub::List);
        assert!(b.json && b.dry_run && b.all);
    }

    #[test]
    fn defaults_match_what_the_tool_is_for() {
        let a = p("verify").unwrap();
        assert_eq!(a.pid_or_default(), 0x1227);
        assert_eq!(a.expect_or_default(), Expect::LibusbK);
        assert_eq!(
            a.method,
            Method::UpdateDriverForPnp,
            "the forced-INF-path API is the default: Windows' compatible-driver list \
             does not offer the libusbK package on this host"
        );
        assert_eq!(a.prefer, Preference::LibusbK);
        assert!(a.state.is_none());
        let l = p("list").unwrap();
        assert_eq!(l.pid, None, "list shows every Apple-VID node by default");
    }

    #[test]
    fn parses_every_option_the_requirements_name() {
        let a = p(
            "bind --pid 1227 --prefer libusb0 --inf oem47.inf --hwid USB\\VID_05AC&PID_1227 \
             --method update --state C:\\tmp\\s.conf --instance USB\\X --json --dry-run",
        )
        .unwrap();
        assert_eq!(a.prefer, Preference::Libusb0);
        assert_eq!(a.inf.as_deref(), Some("oem47.inf"));
        assert_eq!(a.hwid.as_deref(), Some("USB\\VID_05AC&PID_1227"));
        assert_eq!(a.method, Method::UpdateDriverForPnp);
        assert_eq!(a.state, Some(PathBuf::from(r"C:\tmp\s.conf")));
        assert_eq!(a.instance.as_deref(), Some("USB\\X"));
        assert!(a.json && a.dry_run);

        let v = p("verify --expect restored --json").unwrap();
        assert_eq!(v.expect, Some(Expect::Restored));
        let v2 = p("verify --expect winusb").unwrap();
        assert_eq!(v2.expect, Some(Expect::WinUsb));
    }

    #[test]
    fn rejects_unknown_flags_subcommands_and_bad_values() {
        assert!(p("--bogus list").unwrap_err().contains("unknown option"));
        assert!(p("frobnicate").unwrap_err().contains("unknown subcommand"));
        assert!(p("").unwrap_err().contains("no subcommand"));
        assert!(p("list extra").unwrap_err().contains("unexpected extra argument"));
        assert!(p("bind --prefer floppy").unwrap_err().contains("driver family"));
        assert!(p("verify --expect banana").unwrap_err().contains("--expect"));
        assert!(p("bind --method telepathy").unwrap_err().contains("--method"));
        assert!(p("bind --state").unwrap_err().contains("needs a value"));
    }

    #[test]
    fn options_belonging_to_another_subcommand_are_refused() {
        assert!(p("list --inf oem46.inf").unwrap_err().contains("only valid for"));
        assert!(p("list --expect libusbK").unwrap_err().contains("only valid for"));
        assert!(p("verify --prefer libusb0").unwrap_err().contains("only valid for"));
        assert!(p("verify --all").unwrap_err().contains("only valid for"));
        assert!(p("bind --expect winusb").unwrap_err().contains("only valid for"));
        assert!(p("verify --method di").unwrap_err().contains("only valid for"));
        // ...but the values that are the default are always allowed.
        assert!(p("verify").is_ok());
        assert!(p("list").is_ok());
    }

    #[test]
    fn help_and_version_win_over_everything() {
        assert_eq!(p("--help").unwrap().sub, Sub::Help);
        assert_eq!(p("-h").unwrap().sub, Sub::Help);
        assert_eq!(p("--version").unwrap().sub, Sub::Version);
        assert_eq!(p("-V").unwrap().sub, Sub::Version);
        // Even with junk after it, help is help.
        assert_eq!(p("--help --pid nonsense").unwrap().sub, Sub::Help);
    }

    #[test]
    fn help_text_documents_the_real_exit_codes_and_grammar() {
        let h = help();
        assert!(h.contains("a9drv <subcommand>"));
        for code in ["0 ok", "2 verification failed", "3 needs elevation", "5 the driver API refused"] {
            assert!(h.contains(code), "help must document {code}");
        }
        assert!(h.contains("never self-elevates"));
        assert!(h.contains("no matching package in the driver store") || h.contains("no matching package"));
        assert!(!h.contains("{version}"), "the version placeholder must be substituted");
    }
}
