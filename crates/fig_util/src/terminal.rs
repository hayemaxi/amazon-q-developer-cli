use std::borrow::Cow;
use std::fmt;
use std::sync::OnceLock;

use anyhow::Context as _;
use fig_os_shim::Context;
use serde::{
    Deserialize,
    Serialize,
};
use std::io::{
    self,
    Read,
    Write,
};
use std::os::unix::io::{
    AsRawFd,
    FromRawFd,
    RawFd,
};
use std::os::unix::process::CommandExt;
use std::path::Path;

use async_trait::async_trait;
use filedescriptor::FileDescriptor;
use nix::fcntl::{
    FcntlArg,
    FdFlag,
    OFlag,
    fcntl,
    open,
};
use nix::libc;
use nix::pty::{
    PtyMaster,
    Winsize,
    grantpt,
    posix_openpt,
    ptsname,
    unlockpt,
};
use nix::sys::signal::{
    SigHandler,
    Signal,
    signal,
};
use nix::sys::stat::{
    Mode,
    umask,
};
use portable_pty::unix::close_random_fds;
use portable_pty::{
    Child,
    PtySize,
};
use tokio::io::unix::AsyncFd;

use std::collections::BTreeMap;
use std::ffi::{
    OsStr,
    OsString,
};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(unix)]
use cfg_if::cfg_if;

nix::ioctl_write_ptr_bad!(ioctl_tiocswinsz, libc::TIOCSWINSZ, Winsize);

/// Terminals that macOS supports
pub const MACOS_TERMINALS: &[Terminal] = &[
    Terminal::Alacritty,
    Terminal::Iterm,
    Terminal::Kitty,
    Terminal::Tabby,
    Terminal::TerminalApp,
    Terminal::VSCodeInsiders,
    Terminal::VSCode,
    Terminal::VSCodium,
    Terminal::WezTerm,
    Terminal::Zed,
    Terminal::Cursor,
    Terminal::CursorNightly,
    Terminal::Rio,
    Terminal::Windsurf,
    Terminal::WindsurfNext,
    Terminal::Ghostty,
    Terminal::Positron,
    Terminal::Trae,
];

/// Terminals that Linux supports
pub const LINUX_TERMINALS: &[Terminal] = &[
    Terminal::Alacritty,
    Terminal::Kitty,
    Terminal::GnomeConsole,
    Terminal::GnomeTerminal,
    Terminal::Guake,
    Terminal::Hyper,
    Terminal::Konsole,
    Terminal::XfceTerminal,
    Terminal::WezTerm,
    Terminal::Tilix,
    Terminal::Terminator,
    Terminal::VSCode,
    Terminal::VSCodeInsiders,
    Terminal::VSCodium,
    Terminal::IntelliJ(None),
    Terminal::Positron,
];

/// Other terminals that figterm should launch within that are not full terminal emulators
pub const SPECIAL_TERMINALS: &[Terminal] = &[
    Terminal::Ssh,
    Terminal::Tmux,
    Terminal::Nvim,
    Terminal::Vim,
    Terminal::Zellij,
];

pub fn current_terminal() -> Option<&'static Terminal> {
    static CURRENT_TERMINAL: OnceLock<Option<Terminal>> = OnceLock::new();
    CURRENT_TERMINAL
        .get_or_init(|| Terminal::parent_terminal(&Context::new()))
        .as_ref()
}

pub fn current_terminal_version() -> Option<&'static str> {
    static CURRENT_TERMINAL_VERSION: OnceLock<Option<String>> = OnceLock::new();
    CURRENT_TERMINAL_VERSION.get_or_init(Terminal::version).as_deref()
}

/// Checks if the current process is inside of one of the pseudoterminals listed under
/// [`SPECIAL_TERMINALS`], returning the terminal if true.
pub fn in_special_terminal(ctx: &Context) -> Option<Terminal> {
    Terminal::from_process_info(ctx, &SPECIAL_TERMINALS.to_vec())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CustomTerminalMacos {
    /// The macOS bundle ID
    pub bundle_id: Option<String>,

    #[serde(default)]
    pub input_method: bool,
    #[serde(default)]
    pub accessibility: bool,
    #[serde(default)]
    pub xterm: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CustomTerminal {
    pub id: String,
    pub name: String,
    pub macos: CustomTerminalMacos,
}

/// All supported terminals
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Terminal {
    /// iTerm 2
    Iterm,
    /// Native macOS terminal
    TerminalApp,
    /// Hyper terminal
    Hyper,
    /// Alacritty terminal
    Alacritty,
    /// Kitty terminal
    Kitty,
    /// VSCode terminal
    VSCode,
    /// VSCode Insiders
    VSCodeInsiders,
    /// VSCodium
    VSCodium,
    /// Tabby
    Tabby,
    /// Nova
    Nova,
    /// Wezterm
    WezTerm,
    /// Gnome Console
    GnomeConsole,
    /// Gnome Terminal
    GnomeTerminal,
    /// KDE Konsole
    Konsole,
    /// Tilix
    Tilix,
    /// Xfce Terminal
    XfceTerminal,
    /// Terminator
    Terminator,
    /// Terminology
    Terminology,
    /// IntelliJ
    IntelliJ(Option<IntelliJVariant>),
    // Zed
    Zed,
    /// Cursor
    Cursor,
    /// Cursor Nightly
    CursorNightly,
    /// Rio <https://github.com/raphamorim/rio>
    Rio,
    /// Guake
    Guake,

    // Other pseudoterminal that we want to launch within
    /// SSH
    Ssh,
    /// Tmux
    Tmux,
    /// Vim
    Vim,
    /// Nvim
    Nvim,
    /// Zellij
    Zellij,
    /// Windsurf
    Windsurf,
    /// Windsurf Next
    WindsurfNext,
    /// Ghostty
    Ghostty,
    /// Positron
    Positron,
    /// Trae
    Trae,

    /// Custom terminal to support user/custom entries
    Custom(CustomTerminal),
}

impl fmt::Display for Terminal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Terminal::Iterm => write!(f, "iTerm 2"),
            Terminal::TerminalApp => write!(f, "macOS"),
            Terminal::Hyper => write!(f, "Hyper"),
            Terminal::Alacritty => write!(f, "Alacritty"),
            Terminal::Kitty => write!(f, "Kitty"),
            Terminal::VSCode => write!(f, "VSCode"),
            Terminal::VSCodeInsiders => write!(f, "VSCode Insiders"),
            Terminal::VSCodium => write!(f, "VSCodium"),
            Terminal::Tabby => write!(f, "Tabby"),
            Terminal::Nova => write!(f, "Nova"),
            Terminal::WezTerm => write!(f, "Wezterm"),
            Terminal::GnomeConsole => write!(f, "Gnome Console"),
            Terminal::GnomeTerminal => write!(f, "Gnome Terminal"),
            Terminal::Konsole => write!(f, "Konsole"),
            Terminal::Tilix => write!(f, "Tilix"),
            Terminal::XfceTerminal => write!(f, "Xfce Terminal"),
            Terminal::Terminator => write!(f, "Terminator"),
            Terminal::Terminology => write!(f, "Terminology"),
            Terminal::Ssh => write!(f, "SSH"),
            Terminal::Tmux => write!(f, "Tmux"),
            Terminal::Vim => write!(f, "Vim"),
            Terminal::Nvim => write!(f, "Nvim"),
            Terminal::Zellij => write!(f, "Zellij"),
            Terminal::IntelliJ(Some(variant)) => write!(f, "{}", variant.application_name()),
            Terminal::IntelliJ(None) => write!(f, "IntelliJ"),
            Terminal::Zed => write!(f, "Zed"),
            Terminal::Cursor => write!(f, "Cursor"),
            Terminal::CursorNightly => write!(f, "Cursor Nightly"),
            Terminal::Rio => write!(f, "Rio"),
            Terminal::Windsurf => write!(f, "Windsurf"),
            Terminal::WindsurfNext => write!(f, "Windsurf Next"),
            Terminal::Guake => write!(f, "Guake"),
            Terminal::Ghostty => write!(f, "Ghostty"),
            Terminal::Positron => write!(f, "Positron"),
            Terminal::Trae => write!(f, "Trae"),
            Terminal::Custom(custom_terminal) => write!(f, "{}", custom_terminal.name),
        }
    }
}

impl Terminal {
    /// Attempts to return the suspected terminal emulator for the current process.
    ///
    /// Note that "special" pseudoterminals like tmux or ssh will not be returned.
    pub fn parent_terminal(ctx: &Context) -> Option<Self> {
        let env = ctx.env();

        #[cfg(target_os = "macos")]
        {
            if let Ok(bundle_id) = env.get("__CFBundleIdentifier") {
                if let Some(term) = Self::from_bundle_id(bundle_id) {
                    return Some(term);
                }
            }
        }

        match env.get("TERM_PROGRAM").ok().as_deref() {
            Some("iTerm.app") => return Some(Terminal::Iterm),
            Some("Apple_Terminal") => return Some(Terminal::TerminalApp),
            Some("Hyper") => return Some(Terminal::Hyper),
            Some("vscode") => match std::env::var("TERM_PROGRAM_VERSION").ok().as_deref() {
                Some(v) if v.contains("insiders") => return Some(Terminal::VSCodeInsiders),
                _ => return Some(Terminal::VSCode),
            },
            Some("Tabby") => return Some(Terminal::Tabby),
            Some("Nova") => return Some(Terminal::Nova),
            Some("WezTerm") => return Some(Terminal::WezTerm),
            Some("guake") => return Some(Terminal::Guake),
            Some("ghostty") => return Some(Terminal::Ghostty),
            _ => (),
        };

        let terminals = match ctx.platform().os() {
            fig_os_shim::Os::Mac => MACOS_TERMINALS,
            fig_os_shim::Os::Linux => LINUX_TERMINALS,
            _ => return None,
        };
        Self::from_process_info(ctx, &terminals.to_vec())
    }

    /// Attempts to return the suspected terminal emulator for the current process according to the
    /// process hierarchy. Only the list provided in `terminals` will be searched for.
    pub fn from_process_info(ctx: &Context, terminals: &Vec<Terminal>) -> Option<Self> {
        let mut option_pid = Some(Box::new(ctx.process_info().current_pid()));
        let (mut curr_depth, max_depth) = (0, 5);
        while curr_depth < max_depth {
            if let Some(pid) = option_pid {
                if let Some(exe) = pid.exe() {
                    if let Some(name) = exe.file_name().and_then(|s| s.to_str()) {
                        for terminal in terminals {
                            if terminal.executable_names().contains(&name) {
                                return Some(terminal.clone());
                            }
                        }
                    }
                }
                if let Some(cmdline) = pid.cmdline() {
                    if let Some(terminal) = Self::try_from_cmdline(&cmdline, terminals) {
                        return Some(terminal.clone());
                    }
                }
                option_pid = pid.parent();
                curr_depth += 1;
            } else {
                break;
            }
        }
        None
    }

    /// Attempts to find the suspected terminal according to the provided `cmdline` - ie,
    /// the value from /proc/pid/cmdline except with null bytes replaced with space.
    ///
    /// Only the list provided in `terminals` will be searched for.
    pub fn try_from_cmdline(cmdline: &str, terminals: &Vec<Terminal>) -> Option<Self> {
        // Special cases for terminals that launch as a script, e.g.
        // `/usr/bin/python3 /usr/bin/terminator`
        let second_arg_terms = &[Terminal::Terminator, Terminal::Guake];
        if second_arg_terms.iter().any(|t| terminals.contains(t)) {
            let second_arg_name = cmdline
                .split(' ')
                .skip(1)
                .take(1)
                .next()
                .and_then(|cmd| cmd.split('/').last());
            if let Some(second_arg_name) = second_arg_name {
                if let Some(term) = second_arg_terms
                    .iter()
                    .find(|t| t.executable_names().contains(&second_arg_name))
                {
                    return Some(term.clone());
                }
            }
        }

        // Default logic that checks the final path element of the first argument.
        let first_arg_name = cmdline
            .split(' ')
            .take(1)
            .next()
            .and_then(|cmd| cmd.split('/').last())
            .map(str::to_string);
        if let Some(first_arg_name) = first_arg_name {
            for terminal in terminals {
                if terminal.executable_names().contains(&first_arg_name.as_str()) {
                    return Some(terminal.clone());
                }
            }
        }

        None
    }

    pub fn version() -> Option<String> {
        static RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
        let re = RE.get_or_init(|| regex::Regex::new("[0-9\\-\\._]+").ok()).as_ref()?;
        let version = std::env::var("TERM_PROGRAM_VERSION").ok()?;
        match re.captures(&version).is_some() {
            true => Some(version),
            false => None,
        }
    }

    pub fn internal_id(&self) -> Cow<'static, str> {
        match self {
            Terminal::Iterm => "iterm".into(),
            Terminal::TerminalApp => "terminal".into(),
            Terminal::Hyper => "hyper".into(),
            Terminal::Alacritty => "alacritty".into(),
            Terminal::Kitty => "kitty".into(),
            Terminal::VSCode => "vscode".into(),
            Terminal::VSCodeInsiders => "vscode-insiders".into(),
            Terminal::VSCodium => "vscodium".into(),
            Terminal::Tabby => "tabby".into(),
            Terminal::Nova => "nova".into(),
            Terminal::WezTerm => "wezterm".into(),
            Terminal::GnomeTerminal => "gnome-terminal".into(),
            Terminal::GnomeConsole => "gnome-console".into(),
            Terminal::Konsole => "konsole".into(),
            Terminal::Tilix => "tilix".into(),
            Terminal::XfceTerminal => "xfce-terminal".into(),
            Terminal::Terminator => "terminator".into(),
            Terminal::Terminology => "terminology".into(),
            Terminal::Ssh => "ssh".into(),
            Terminal::Tmux => "tmux".into(),
            Terminal::Vim => "vim".into(),
            Terminal::Nvim => "nvim".into(),
            Terminal::Zellij => "zellij".into(),
            Terminal::Zed => "zed".into(),
            Terminal::IntelliJ(ide) => match ide {
                Some(variant) => format!("intellij-{}", variant.internal_id()).into(),
                None => "intellij".into(),
            },
            Terminal::Cursor => "cursor".into(),
            Terminal::CursorNightly => "cursor-nightly".into(),
            Terminal::Rio => "rio".into(),
            Terminal::Windsurf => "windsurf".into(),
            Terminal::WindsurfNext => "windsurf-next".into(),
            Terminal::Guake => "guake".into(),
            Terminal::Ghostty => "ghostty".into(),
            Terminal::Positron => "positron".into(),
            Terminal::Trae => "trae".into(),
            Terminal::Custom(custom_terminal) => custom_terminal.id.clone().into(),
        }
    }

    /// Get the bundle identifier for the terminal
    /// Note: this does not gracefully handle terminals that have changed bundle identifiers
    /// recently such as VSCodium & Alacritty. We default to the current identifier.
    pub fn to_bundle_id(&self) -> Option<Cow<'static, str>> {
        match self {
            Terminal::Iterm => Some("com.googlecode.iterm2".into()),
            Terminal::TerminalApp => Some("com.apple.Terminal".into()),
            Terminal::Hyper => Some("co.zeit.hyper".into()),
            Terminal::Alacritty => Some("org.alacritty".into()),
            Terminal::Kitty => Some("net.kovidgoyal.kitty".into()),
            Terminal::VSCode => Some("com.microsoft.VSCode".into()),
            Terminal::VSCodeInsiders => Some("com.microsoft.VSCodeInsiders".into()),
            Terminal::VSCodium => Some("com.vscodium".into()),
            Terminal::Tabby => Some("org.tabby".into()),
            Terminal::Nova => Some("com.panic.Nova".into()),
            Terminal::WezTerm => Some("com.github.wez.wezterm".into()),
            Terminal::IntelliJ(Some(variant)) => Some(variant.bundle_identifier().into()),
            Terminal::Zed => Some("dev.zed.Zed".into()),
            Terminal::Cursor => Some("com.todesktop.230313mzl4w4u92".into()),
            Terminal::CursorNightly => Some("com.todesktop.23052492jqa5xjo".into()),
            Terminal::Rio => Some("com.raphaelamorim.rio".into()),
            Terminal::Windsurf => Some("com.exafunction.windsurf".into()),
            Terminal::WindsurfNext => Some("com.exafunction.windsurf-next".into()),
            Terminal::Ghostty => Some("com.mitchellh.ghostty".into()),
            Terminal::Positron => Some("co.posit.positron".into()),
            Terminal::Trae => Some("com.trae.app".into()),
            Terminal::Custom(custom_terminal) => custom_terminal.macos.bundle_id.clone().map(Cow::Owned),
            _ => None,
        }
    }

    pub fn from_bundle_id(bundle: impl AsRef<str>) -> Option<Self> {
        let bundle = bundle.as_ref();
        let res = match bundle {
            "com.googlecode.iterm2" => Terminal::Iterm,
            "com.apple.Terminal" => Terminal::TerminalApp,
            "co.zeit.hyper" => Terminal::Hyper,
            "io.alacritty" | "org.alacritty" => Terminal::Alacritty,
            "net.kovidgoyal.kitty" => Terminal::Kitty,
            "com.microsoft.VSCode" => Terminal::VSCode,
            "com.microsoft.VSCodeInsiders" => Terminal::VSCodeInsiders,
            "com.vscodium" | "com.visualstudio.code.oss" => Terminal::VSCodium,
            "org.tabby" => Terminal::Tabby,
            "com.panic.Nova" => Terminal::Nova,
            "com.github.wez.wezterm" => Terminal::WezTerm,
            "dev.zed.Zed" => Terminal::Zed,
            "com.todesktop.230313mzl4w4u92" => Terminal::Cursor,
            "com.todesktop.23052492jqa5xjo" => Terminal::CursorNightly,
            "com.raphaelamorim.rio" => Terminal::Rio,
            "com.exafunction.windsurf" => Terminal::Windsurf,
            "com.exafunction.windsurf-next" => Terminal::WindsurfNext,
            "com.mitchellh.ghostty" => Terminal::Ghostty,
            "co.posit.positron" => Terminal::Positron,
            "com.trae.app" => Terminal::Trae,
            // TODO: the following line does not account for Android Studio
            _ if bundle.starts_with("com.jetbrains.") | bundle.starts_with("com.google.") => {
                Terminal::IntelliJ(IntelliJVariant::from_bundle_id(bundle))
            },
            _ => return None,
        };

        Some(res)
    }

    pub fn supports_macos_input_method(&self) -> bool {
        matches!(
            self,
            Terminal::Alacritty
                | Terminal::Kitty
                | Terminal::Nova
                | Terminal::WezTerm
                | Terminal::IntelliJ(_)
                | Terminal::Zed
                | Terminal::Rio
                | Terminal::Ghostty
        ) || self.as_custom().is_some_and(|c| c.macos.input_method)
    }

    pub fn supports_macos_accessibility(&self) -> bool {
        matches!(
            self,
            Terminal::Iterm
                | Terminal::TerminalApp
                | Terminal::VSCode
                | Terminal::VSCodeInsiders
                | Terminal::VSCodium
                | Terminal::Hyper
                | Terminal::Tabby
        ) || self.as_custom().is_some_and(|c| c.macos.accessibility)
    }

    pub fn is_xterm(&self) -> bool {
        matches!(
            self,
            Terminal::VSCode
                | Terminal::VSCodeInsiders
                | Terminal::VSCodium
                | Terminal::Hyper
                | Terminal::Tabby
                | Terminal::Cursor
                | Terminal::CursorNightly
                | Terminal::Windsurf
                | Terminal::WindsurfNext
                | Terminal::Trae
        ) || self.as_custom().is_some_and(|c| c.macos.xterm)
    }

    pub fn executable_names(&self) -> &'static [&'static str] {
        match self {
            Terminal::VSCode => &["code"],
            Terminal::VSCodeInsiders => &["code-insiders"],
            Terminal::Alacritty => &["alacritty"],
            Terminal::Kitty => &["kitty"],
            Terminal::GnomeConsole => &["kgx"],
            Terminal::GnomeTerminal => &["gnome-terminal-server"],
            Terminal::Konsole => &["konsole"],
            Terminal::Tilix => &["tilix"],
            Terminal::XfceTerminal => &["xfce4-terminal"],
            Terminal::Terminology => &["terminology"],
            Terminal::WezTerm => &["wezterm", "wezterm-gui"],
            Terminal::Hyper => &["hyper"],
            Terminal::Tabby => &["tabby"],
            Terminal::Terminator => &["terminator"],
            Terminal::Zed => &["zed"],
            Terminal::Cursor => &["Cursor", "cursor"],
            Terminal::CursorNightly => &["Cursor Nightly", "cursor-nightly"],
            Terminal::Rio => &["rio"],
            Terminal::Windsurf => &["windsurf"],
            Terminal::WindsurfNext => &["windsurf-next"],
            Terminal::Guake => &["guake"],
            Terminal::Ghostty => &["ghostty"],
            Terminal::Positron => &["positron"],
            Terminal::Trae => &["trae"],

            Terminal::Ssh => &["sshd"],
            Terminal::Tmux => &["tmux", "tmux: server"],
            Terminal::Vim => &["vim"],
            Terminal::Nvim => &["nvim"],
            Terminal::Zellij => &["zellij"],

            _ => &[],
        }
    }

    /// Returns the "Class" part of the WM_CLASS property.
    pub fn wm_class(&self) -> Option<&'static str> {
        match self {
            Terminal::VSCode => Some("Code"),
            Terminal::VSCodeInsiders => Some("Vscode-insiders"),
            Terminal::GnomeConsole => Some("Kgx"),
            Terminal::GnomeTerminal => Some("Gnome-terminal"),
            Terminal::Guake => Some("Guake"),
            Terminal::Hyper => Some("Hyper"),
            Terminal::Konsole => Some("konsole"),
            Terminal::Tilix => Some("Tilix"),
            Terminal::Alacritty => Some("Alacritty"),
            Terminal::Kitty => Some("kitty"),
            Terminal::XfceTerminal => Some("Xfce4-terminal"),
            Terminal::Terminator => Some("Terminator"),
            Terminal::Terminology => Some("terminology"),
            Terminal::WezTerm => Some("org.wezfurlong.wezterm"),
            Terminal::Tabby => Some("tabby"),
            Terminal::IntelliJ(Some(IntelliJVariant::IdeaCE)) => Some("jetbrains-idea-ce"),
            _ => None,
        }
    }

    /// Returns the "Instance" part of the WM_CLASS property.
    pub fn wm_class_instance(&self) -> Option<&'static str> {
        match self {
            Terminal::GnomeConsole => Some("org.gnome.Console"),
            Terminal::GnomeTerminal => Some("gnome-terminal-server"),
            Terminal::Guake => Some("guake"),
            Terminal::Hyper => Some("hyper"),
            Terminal::Terminator => Some("terminator"),
            Terminal::Tilix => Some("tilix"),
            // Many terminals seem to use the same name for both, falling back to Class name
            // as a default.
            _ => self.wm_class(),
        }
    }

    pub fn is_jetbrains_terminal() -> bool {
        // Handles all official JetBrain IDEs + Android Studio
        match std::env::var("TERMINAL_EMULATOR") {
            Ok(v) => v == "JetBrains-JediTerm",
            Err(_) => false,
        }
    }

    pub fn supports_fancy_boxes(&self) -> bool {
        !matches!(
            self,
            Terminal::VSCode
                | Terminal::VSCodeInsiders
                | Terminal::VSCodium
                | Terminal::Cursor
                | Terminal::CursorNightly
                | Terminal::Windsurf
                | Terminal::WindsurfNext
                | Terminal::Trae
        )
    }

    pub fn positioning_kind(&self) -> PositioningKind {
        match self {
            Terminal::Konsole => PositioningKind::Logical,
            _ => PositioningKind::Physical,
        }
    }

    /// Other pseudoterminal that we want to launch within
    pub fn is_special(&self) -> bool {
        matches!(
            self,
            Terminal::Ssh | Terminal::Tmux | Terminal::Vim | Terminal::Nvim | Terminal::Zellij
        )
    }

    pub fn as_custom(&self) -> Option<&CustomTerminal> {
        match self {
            Terminal::Custom(custom) => Some(custom),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum PositioningKind {
    Logical,
    Physical,
}

macro_rules! intellij_variants {
    ($($name:ident { org: $organization:expr, internal_id: $internal_id:expr, name: $application_name:expr, bundle: $bundle_identifier:expr },)*) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "kebab-case")]
        pub enum IntelliJVariant {
            $(
                $name,
            )*
        }

        impl IntelliJVariant {
            pub const fn all() -> &'static [IntelliJVariant] {
                &[$(IntelliJVariant::$name,)*]
            }

            pub fn application_name(&self) -> &'static str {
                match self {
                    $(
                        IntelliJVariant::$name => $application_name,
                    )*
                }
            }

            pub fn organization(&self) -> &'static str {
                match self {
                    $(
                        IntelliJVariant::$name => $organization,
                    )*
                }
            }

            pub fn bundle_identifier(&self) -> &'static str {
                match self {
                    $(
                        IntelliJVariant::$name => $bundle_identifier,
                    )*
                }
            }

            pub fn internal_id(&self) -> &'static str {
                match self {
                    $(
                        IntelliJVariant::$name => $internal_id,
                    )*
                }
            }

            pub fn from_bundle_id(bundle_id: &str) -> Option<IntelliJVariant> {
                match bundle_id {
                    $(
                        $bundle_identifier => Some(IntelliJVariant::$name),
                    )*
                    _ => None,
                }
            }
        }
    };
}

intellij_variants! {
    IdeaUltimate {
        org: "JetBrains",
        internal_id: "idea-ultimate",
        name: "IDEA Ultimate",
        bundle: "com.jetbrains.intellij"
    },
    IdeaUltimateEap {
        org: "JetBrains",
        internal_id: "idea-ultimate-eap",
        name: "IDEA Ultimate EAP",
        bundle: "com.jetbrains.intellij-EAP"
    },
    IdeaCE {
        org: "JetBrains",
        internal_id: "idea-ce",
        name: "IDEA Community",
        bundle: "com.jetbrains.intellij.ce"
    },
    WebStorm {
        org: "JetBrains",
        internal_id: "webstorm",
        name: "WebStorm",
        bundle: "com.jetbrains.WebStorm"
    },
    GoLand {
        org: "JetBrains",
        internal_id: "goland",
        name: "GoLand",
        bundle: "com.jetbrains.goland"
    },
    PhpStorm {
        org: "JetBrains",
        internal_id: "phpstorm",
        name: "PhpStorm",
        bundle: "com.jetbrains.PhpStorm"
    },
    PyCharm {
        org: "JetBrains",
        internal_id: "pycharm",
        name: "PyCharm Professional",
        bundle: "com.jetbrains.pycharm"
    },
    PyCharmCE {
        org: "JetBrains",
        internal_id: "pycharm-ce",
        name: "PyCharm Community",
        bundle: "com.jetbrains.pycharm.ce"
    },
    AppCode {
        org: "JetBrains",
        internal_id: "appcode",
        name: "AppCode",
        bundle: "com.jetbrains.AppCode"
    },
    CLion {
        org: "JetBrains",
        internal_id: "clion",
        name: "CLion",
        bundle: "com.jetbrains.CLion"
    },
    Rider {
        org: "JetBrains",
        internal_id: "rider",
        name: "Rider",
        bundle: "com.jetbrains.rider"
    },
    RubyMine {
        org: "JetBrains",
        internal_id: "rubymine",
        name: "RubyMine",
        bundle: "com.jetbrains.rubymine"
    },
    DataSpell {
        org: "JetBrains",
        internal_id: "dataspell",
        name: "DataSpell",
        bundle: "com.jetbrains.dataspell"
    },
    DataGrip {
        org: "JetBrains",
        internal_id: "datagrip",
        name: "DataGrip",
        bundle: "com.jetbrains.datagrip"
    },
    RustRover {
        org: "JetBrains",
        internal_id: "rustrover",
        name: "Rust Rover",
        bundle: "com.jetbrains.rustrover"
    },
    RustRoverEap {
        org: "JetBrains",
        internal_id: "rustrover-EAP",
        name: "Rust Rover EAP",
        bundle: "com.jetbrains.rustrover-EAP"
    },
    AndroidStudio {
        org: "Google",
        internal_id: "android-studio",
        name: "Android Studio",
        bundle: "com.google.android.studio"
    },
}

impl IntelliJVariant {
    pub fn from_product_code(from: &str) -> Option<Self> {
        Some(match from {
            "IU" => IntelliJVariant::IdeaUltimate,
            "IC" => IntelliJVariant::IdeaCE,
            "PC" => IntelliJVariant::PyCharmCE,
            _ => return None,
        })
    }
}


struct UnixSlavePty {
    name: String,
    fd: FileDescriptor,
}

struct UnixMasterPty {
    fd: PtyMaster,
}

struct UnixAsyncMasterPty {
    fd: AsyncFd<PtyMaster>,
}

/// Helper function to set the close-on-exec flag for a raw descriptor
fn cloexec(fd: RawFd) -> anyhow::Result<()> {
    let flags = fcntl(fd, FcntlArg::F_GETFD)?;
    fcntl(
        fd,
        FcntlArg::F_SETFD(FdFlag::from_bits_truncate(flags) | FdFlag::FD_CLOEXEC),
    )?;
    Ok(())
}

/// Open a pseudoterminal
pub fn open_pty(pty_size: &PtySize) -> anyhow::Result<PtyPair> {
    // Open a new pseudoterminal master
    // The pseudoterminal must be initialized with O_NONBLOCK since on macOS, the
    // it can not be safely set with fcntl() later on.
    // https://github.com/pkgw/stund/blob/master/tokio-pty-process/src/lib.rs#L127-L133
    cfg_if::cfg_if! {
        if #[cfg(any(target_os = "macos", target_os = "linux"))] {
            let oflag = OFlag::O_RDWR | OFlag::O_NONBLOCK;
        } else if #[cfg(target_os = "freebsd")] {
            let oflag = OFlag::O_RDWR;
        }
    }
    let master_pty: PtyMaster = posix_openpt(oflag).context("Failed to openpt")?;

    // Allow pseudoterminal pair to be generated
    grantpt(&master_pty).context("Failed to grantpt")?;
    unlockpt(&master_pty).context("Failed to unlockpt")?;

    // Get the name of the pseudoterminal
    // SAFETY: This is done before any threads are spawned, thus it being
    // non thread safe is not an issue
    let pty_name = unsafe { ptsname(&master_pty) }?;
    let slave_pty = open(Path::new(&pty_name), OFlag::O_RDWR, Mode::empty())?;

    // let termios = tcgetattr(STDIN_FILENO)
    //    .context("Failed to get terminal attributes")?;
    // tcsetattr(slave_pty, SetArg::TCSANOW, termios)?;
    let winsize = Winsize {
        ws_row: pty_size.rows,
        ws_col: pty_size.cols,
        ws_xpixel: pty_size.pixel_width,
        ws_ypixel: pty_size.pixel_height,
    };
    unsafe { ioctl_tiocswinsz(slave_pty, &winsize) }?;

    #[cfg(target_os = "freebsd")]
    set_nonblocking(master_pty.as_raw_fd()).context("Failed to set nonblocking")?;

    let master = UnixMasterPty { fd: master_pty };
    let slave = UnixSlavePty {
        name: pty_name,
        fd: unsafe { FileDescriptor::from_raw_fd(slave_pty) },
    };

    // Ensure that these descriptors will get closed when we execute
    // the child process. This is done after constructing the Pty
    // instances so that we ensure that the Ptys get drop()'d if
    // the cloexec() functions fail (unlikely!).
    cloexec(master.fd.as_raw_fd())?;
    cloexec(slave.fd.as_raw_fd())?;

    Ok(PtyPair {
        master: Box::new(master),
        slave: Box::new(slave),
    })
}

impl SlavePty for UnixSlavePty {
    fn spawn_command(&self, builder: CommandBuilder) -> anyhow::Result<Box<dyn Child + Send + Sync>> {
        let configured_mask = builder.umask;
        let mut cmd = builder.as_command()?;

        cmd.stdin(self.fd.as_stdio()?)
            .stdout(self.fd.as_stdio()?)
            .stderr(self.fd.as_stdio()?);

        let pre_exec_fn = move || {
            // Clean up a few things before we exec the program
            // Clear out any potentially problematic signal
            // dispositions that we might have inherited
            for signo in [
                Signal::SIGCHLD,
                Signal::SIGHUP,
                Signal::SIGINT,
                Signal::SIGQUIT,
                Signal::SIGTERM,
                Signal::SIGALRM,
            ] {
                unsafe { signal(signo, SigHandler::SigDfl) }?;
            }

            // Establish ourselves as a session leader.
            nix::unistd::setsid()?;

            // Clippy wants us to explicitly cast TIOCSCTTY using
            // type::from(), but the size and potentially signedness
            // are system dependent, which is why we're using `as _`.
            // Suppress this lint for this section of code.
            {
                // Set the pty as the controlling terminal.
                // Failure to do this means that delivery of
                // SIGWINCH won't happen when we resize the
                // terminal, among other undesirable effects.
                if unsafe { libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 } {
                    return Err(io::Error::last_os_error());
                }
            }

            close_random_fds();

            if let Some(mode) = configured_mask {
                umask(mode);
            }

            Ok(())
        };

        unsafe { cmd.pre_exec(pre_exec_fn) };

        let mut child = cmd.spawn()?;

        // Ensure that we close out the slave fds that Child retains;
        // they are not what we need (we need the master side to reference
        // them) and won't work in the usual way anyway.
        // In practice these are None, but it seems best to be move them
        // out in case the behavior of Command changes in the future.
        child.stdin.take();
        child.stdout.take();
        child.stderr.take();

        Ok(Box::new(child))
    }

    fn get_name(&self) -> Option<String> {
        Some(self.name.clone())
    }
}

#[async_trait]
impl AsyncMasterPty for UnixAsyncMasterPty {
    async fn read(&mut self, buff: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable_mut().await?;

            match guard.try_io(|inner| inner.get_mut().read(buff)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    async fn write(&mut self, buff: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.writable_mut().await?;

            match guard.try_io(|inner| inner.get_mut().write(buff)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    fn resize(&self, size: PtySize) -> anyhow::Result<()> {
        let ws_size = Winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: size.pixel_width,
            ws_ypixel: size.pixel_height,
        };

        let fd = self.fd.as_raw_fd();
        let res = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ as _, &ws_size as *const _) };

        if res != 0 {
            anyhow::bail!("failed to ioctl(TIOCSWINSZ): {:?}", io::Error::last_os_error());
        }

        Ok(())
    }
}

impl MasterPty for UnixMasterPty {
    fn get_async_master_pty(self: Box<Self>) -> anyhow::Result<Box<dyn AsyncMasterPty + Send + Sync>> {
        Ok(Box::new(UnixAsyncMasterPty {
            fd: AsyncFd::new(self.fd).context("Failed to create AsyncFd")?,
        }))
    }
}

impl AsRawFd for UnixMasterPty {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
struct EnvEntry {
    /// Whether or not this environment variable came from the base environment,
    /// as opposed to having been explicitly set by the caller.
    is_from_base_env: bool,

    /// For case-insensitive platforms, the environment variable key in its preferred casing.
    preferred_key: OsString,

    /// The environment variable value.
    value: OsString,
}

impl EnvEntry {
    fn map_key(k: OsString) -> OsString {
        cfg_if! {
            if #[cfg(windows)] {
                // Best-effort lowercase transformation of an os string
                match k.to_str() {
                    Some(s) => s.to_lowercase().into(),
                    None => k,
                }
            } else {
                k
            }
        }
    }
}

fn get_base_env() -> BTreeMap<OsString, EnvEntry> {
    std::env::vars_os()
        .map(|(key, value)| {
            (EnvEntry::map_key(key.clone()), EnvEntry {
                is_from_base_env: true,
                preferred_key: key,
                value,
            })
        })
        .collect()
}

/// `CommandBuilder` is used to prepare a command to be spawned into a pty.
/// The interface is intentionally similar to that of `std::process::Command`.
#[derive(Clone, Debug, PartialEq)]
pub struct CommandBuilder {
    args: Vec<OsString>,
    envs: BTreeMap<OsString, EnvEntry>,
    cwd: Option<OsString>,
    #[cfg(unix)]
    pub umask: Option<nix::sys::stat::Mode>,
}

impl CommandBuilder {
    /// Create a new builder instance with `argv[0]` set to the specified
    /// program.
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        Self {
            args: vec![program.as_ref().to_owned()],
            envs: get_base_env(),
            cwd: None,
            #[cfg(unix)]
            umask: None,
        }
    }

    /// Create a new builder instance from a pre-built argument vector
    pub fn from_argv(args: Vec<OsString>) -> Self {
        Self {
            args,
            envs: get_base_env(),
            cwd: None,
            #[cfg(unix)]
            umask: None,
        }
    }

    /// Create a new builder instance that will run some idea of a default
    /// program.  Such a builder will panic if `arg` is called on it.
    pub fn new_default_prog() -> Self {
        Self {
            args: vec![],
            envs: get_base_env(),
            cwd: None,
            #[cfg(unix)]
            umask: None,
        }
    }

    /// Returns true if this builder was created via `new_default_prog`
    pub fn is_default_prog(&self) -> bool {
        self.args.is_empty()
    }

    /// Append an argument to the current command line.
    /// Will panic if called on a builder created via `new_default_prog`.
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) {
        if self.is_default_prog() {
            panic!("attempted to add args to a default_prog builder");
        }
        self.args.push(arg.as_ref().to_owned());
    }

    /// Append a sequence of arguments to the current command line
    pub fn args<I, S>(&mut self, args: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for arg in args {
            self.arg(arg);
        }
    }

    pub fn get_argv(&self) -> &Vec<OsString> {
        &self.args
    }

    pub fn get_argv_mut(&mut self) -> &mut Vec<OsString> {
        &mut self.args
    }

    /// Override the value of an environmental variable
    pub fn env<K, V>(&mut self, key: K, value: V)
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        let key: OsString = key.as_ref().into();
        let value: OsString = value.as_ref().into();
        self.envs.insert(EnvEntry::map_key(key.clone()), EnvEntry {
            is_from_base_env: false,
            preferred_key: key,
            value,
        });
    }

    pub fn env_remove<K>(&mut self, key: K)
    where
        K: AsRef<OsStr>,
    {
        let key = key.as_ref().into();
        self.envs.remove(&EnvEntry::map_key(key));
    }

    pub fn env_clear(&mut self) {
        self.envs.clear();
    }

    fn get_env<K>(&self, key: K) -> Option<&OsStr>
    where
        K: AsRef<OsStr>,
    {
        let key = key.as_ref().into();
        self.envs.get(&EnvEntry::map_key(key)).map(
            |EnvEntry {
                 is_from_base_env: _,
                 preferred_key: _,
                 value,
             }| value.as_os_str(),
        )
    }

    pub fn cwd<D>(&mut self, dir: D)
    where
        D: AsRef<OsStr>,
    {
        self.cwd = Some(dir.as_ref().to_owned());
    }

    pub fn clear_cwd(&mut self) {
        self.cwd.take();
    }

    pub fn get_cwd(&self) -> Option<&OsString> {
        self.cwd.as_ref()
    }

    /// Iterate over the configured environment. Only includes environment
    /// variables set by the caller via `env`, not variables set in the base
    /// environment.
    pub fn iter_extra_env_as_str(&self) -> impl Iterator<Item = (&str, &str)> {
        self.envs.values().filter_map(
            |EnvEntry {
                 is_from_base_env,
                 preferred_key,
                 value,
             }| {
                if *is_from_base_env {
                    None
                } else {
                    let key = preferred_key.to_str()?;
                    let value = value.to_str()?;
                    Some((key, value))
                }
            },
        )
    }

    /// Return the configured command and arguments as a single string,
    /// quoted per the unix shell conventions.
    pub fn as_unix_command_line(&self) -> anyhow::Result<String> {
        let mut strs = vec![];
        for arg in &self.args {
            let s = arg
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("argument cannot be represented as utf8"))?;
            strs.push(s);
        }
        shlex::try_join(strs).map_err(|e| anyhow::anyhow!("Failed to join command arguments: {}", e))
    }
}

#[cfg(unix)]
impl CommandBuilder {
    pub fn umask(&mut self, mask: Option<nix::sys::stat::Mode>) {
        self.umask = mask;
    }

    fn resolve_path(&self) -> Option<&OsStr> {
        self.get_env("PATH")
    }

    fn search_path(&self, exe: &OsStr, cwd: &OsStr) -> anyhow::Result<OsString> {
        use std::path::Path;
        let exe_path: &Path = exe.as_ref();
        if exe_path.is_relative() {
            let cwd: &Path = cwd.as_ref();
            let abs_path = cwd.join(exe_path);
            if abs_path.exists() {
                return Ok(abs_path.into_os_string());
            }

            if let Some(path) = self.resolve_path() {
                for path in std::env::split_paths(&path) {
                    let candidate = path.join(exe);
                    if candidate.exists() {
                        return Ok(candidate.into_os_string());
                    }
                }
            }
            anyhow::bail!(
                "Unable to spawn {} because it doesn't exist on the filesystem \
                and was not found in PATH",
                exe_path.display()
            );
        } else {
            if !exe_path.exists() {
                anyhow::bail!(
                    "Unable to spawn {} because it doesn't exist on the filesystem",
                    exe_path.display()
                );
            }

            Ok(exe.to_owned())
        }
    }

    /// Convert the CommandBuilder to a `std::process::Command` instance.
    pub fn as_command(&self) -> anyhow::Result<std::process::Command> {
        use std::os::unix::process::CommandExt;

        let home = self.get_home_dir()?;
        let dir: &OsStr = self
            .cwd
            .as_deref()
            .filter(|dir| std::path::Path::new(dir).is_dir())
            .unwrap_or_else(|| home.as_ref());

        let mut cmd = if self.is_default_prog() {
            let shell = self.get_shell()?;

            let mut cmd = std::process::Command::new(&shell);

            // Run the shell as a login shell by prefixing the shell's
            // basename with `-` and setting that as argv0
            let basename = shell.rsplit('/').next().unwrap_or(&shell);
            cmd.arg0(format!("-{basename}"));
            cmd
        } else {
            let resolved = self.search_path(&self.args[0], dir)?;
            let mut cmd = std::process::Command::new(resolved);
            cmd.arg0(&self.args[0]);
            cmd.args(&self.args[1..]);
            cmd
        };

        cmd.current_dir(dir);

        cmd.env_clear();
        cmd.envs(self.envs.values().map(
            |EnvEntry {
                 is_from_base_env: _,
                 preferred_key,
                 value,
             }| (preferred_key.as_os_str(), value.as_os_str()),
        ));

        Ok(cmd)
    }

    /// Determine which shell to run.
    /// We take the contents of the $SHELL env var first, then
    /// fall back to looking it up from the password database.
    pub fn get_shell(&self) -> anyhow::Result<String> {
        if let Some(shell) = self.get_env("SHELL").and_then(OsStr::to_str) {
            return Ok(shell.into());
        }

        let ent = unsafe { libc::getpwuid(libc::getuid()) };
        if ent.is_null() {
            Ok("/bin/sh".into())
        } else {
            use std::ffi::CStr;
            use std::str;
            let shell = unsafe { CStr::from_ptr((*ent).pw_shell) };
            shell.to_str().map(str::to_owned).context("failed to resolve shell")
        }
    }

    fn get_home_dir(&self) -> anyhow::Result<String> {
        if let Some(home_dir) = self.get_env("HOME").and_then(OsStr::to_str) {
            return Ok(home_dir.into());
        }

        let ent = unsafe { libc::getpwuid(libc::getuid()) };
        if ent.is_null() {
            Ok("/".into())
        } else {
            use std::ffi::CStr;
            use std::str;
            let home = unsafe { CStr::from_ptr((*ent).pw_dir) };
            home.to_str().map(str::to_owned).context("failed to resolve home dir")
        }
    }
}

#[async_trait]
pub trait AsyncMasterPty {
    async fn read(&mut self, buff: &mut [u8]) -> io::Result<usize>;
    async fn write(&mut self, buff: &[u8]) -> io::Result<usize>;
    fn resize(&self, size: PtySize) -> anyhow::Result<()>;
}

#[async_trait]
pub trait AsyncMasterPtyExt: AsyncMasterPty {
    async fn write_all(&mut self, mut buff: &[u8]) -> io::Result<()> {
        while !buff.is_empty() {
            match self.write(buff).await {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    ));
                },
                Ok(n) => buff = &buff[n..],
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {},
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

impl<T: AsyncMasterPty + ?Sized> AsyncMasterPtyExt for T {}

pub trait MasterPty {
    fn get_async_master_pty(self: Box<Self>) -> anyhow::Result<Box<dyn AsyncMasterPty + Send + Sync>>;
}

pub trait SlavePty {
    fn spawn_command(&self, builder: CommandBuilder) -> anyhow::Result<Box<dyn Child + Send + Sync>>;
    fn get_name(&self) -> Option<String>;
}

pub struct PtyPair {
    // slave is listed first so that it is dropped first.
    // The drop order is stable and specified by rust rfc 1857
    pub slave: Box<dyn SlavePty + Send>,
    pub master: Box<dyn MasterPty + Send>,
}


#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use fig_os_shim::process_info::TestExe;
    use fig_os_shim::{
        Os,
        ProcessInfo,
    };

    use super::*;

    fn make_context<T: Into<TestExe>>(os: Os, processes: Vec<T>) -> Arc<Context> {
        Context::builder()
            .with_os(os)
            .with_process_info(ProcessInfo::from_exes(processes))
            .build()
    }

    #[test]
    fn test_from_process_info() {
        Terminal::from_process_info(&Context::new(), &MACOS_TERMINALS.to_vec());

        let ctx = make_context(Os::Linux, vec!["q", "fish", "wezterm"]);
        assert_eq!(
            Terminal::from_process_info(&ctx, &LINUX_TERMINALS.to_vec()),
            Some(Terminal::WezTerm)
        );

        let ctx = make_context(Os::Linux, vec!["q", "bash", "tmux"]);
        assert_eq!(
            Terminal::from_process_info(&ctx, &LINUX_TERMINALS.to_vec()),
            None,
            "Special terminals should return None"
        );

        let ctx = make_context(Os::Linux, vec!["cargo", "cargo", "q", "bash", "tmux", "wezterm"]);
        assert_eq!(
            Terminal::from_process_info(&ctx, &LINUX_TERMINALS.to_vec()),
            None,
            "Max search depth reached should return None"
        );

        let ctx = make_context(Os::Linux, vec![
            (Some("q"), None),
            (Some("python3"), Some("/usr/bin/python3 /usr/bin/terminator")),
        ]);
        assert_eq!(
            Terminal::from_process_info(&ctx, &LINUX_TERMINALS.to_vec()),
            Some(Terminal::Terminator),
            "should return terminator"
        );

        let ctx = make_context(Os::Linux, vec![
            (Some("q"), None),
            (Some("python3"), Some("/usr/bin/python3 /usr/bin/guake")),
        ]);
        assert_eq!(
            Terminal::from_process_info(&ctx, &LINUX_TERMINALS.to_vec()),
            Some(Terminal::Guake),
            "should return guake"
        );
    }
}
