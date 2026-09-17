//! # IDE Extension Discovery BOF
//!
//! Enumerates bounded per-user extension directories for common Visual Studio
//! Code-compatible editors and remote editor profiles. It reports directory
//! identities and whether a package manifest exists without reading its content.
//!
//! ## MITRE ATT&CK
//! - T1083 - File and Directory Discovery
//!
//! ## Arguments
//! None.

#![no_std]

mod fs;

use fs::{children, environment, join, metadata};
use rustbof::println;

const ROOTS: &[(&str, &str, &str)] = &[
    ("USERPROFILE", ".vscode\\extensions", "VS Code"),
    (
        "USERPROFILE",
        ".vscode-insiders\\extensions",
        "VS Code Insiders",
    ),
    ("USERPROFILE", ".vscode-oss\\extensions", "VS Code OSS"),
    ("USERPROFILE", ".cursor\\extensions", "Cursor"),
    ("USERPROFILE", ".windsurf\\extensions", "Windsurf"),
    (
        "USERPROFILE",
        ".codeium\\windsurf\\extensions",
        "Windsurf Codeium",
    ),
    ("LOCALAPPDATA", "Zed\\extensions\\installed", "Zed"),
    (
        "USERPROFILE",
        ".vscode-server\\extensions",
        "VS Code Server",
    ),
    ("USERPROFILE", ".cursor-server\\extensions", "Cursor Server"),
    (
        "USERPROFILE",
        ".vscode-remote\\extensions",
        "VS Code Remote",
    ),
];

#[rustbof::main]
fn main() {
    println!("IDE extension discovery\n");
    let profile = environment("USERPROFILE").ok();
    let local = environment("LOCALAPPDATA").ok();
    let mut roots = 0usize;
    let mut extensions = 0usize;
    let mut limited = false;

    for (base, relative, label) in ROOTS {
        let base = if *base == "USERPROFILE" {
            profile.as_deref()
        } else {
            local.as_deref()
        };
        let Some(base) = base else {
            continue;
        };
        let path = join(base, relative);
        let Ok(entries) = children(&path, 256) else {
            continue;
        };
        roots += 1;
        println!("{} | {}", label, path);
        for entry in entries {
            if entry.metadata.is_directory && !entry.metadata.is_reparse_point {
                let manifest = join(&entry.path, "package.json");
                if metadata(&manifest).is_ok() {
                    println!("  {} | manifest=yes", entry.name);
                    extensions += 1;
                }
                if extensions >= 1024 {
                    limited = true;
                    break;
                }
            }
        }
        if limited {
            break;
        }
    }

    println!(
        "\nRoots found: {} | extension manifests: {}{}",
        roots,
        extensions,
        if limited {
            " | global limit reached"
        } else {
            ""
        }
    );
}
