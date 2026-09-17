//! # AI Development Surface BOF
//!
//! Reports the presence of common local AI applications, coding-agent profiles,
//! editor storage, and MCP configuration files. It does not read configuration
//! contents, tokens, session data, or prompts.
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

struct Candidate {
    base: &'static str,
    relative: &'static str,
    label: &'static str,
}

const CANDIDATES: &[Candidate] = &[
    Candidate {
        base: "USERPROFILE",
        relative: ".codex",
        label: "Codex profile",
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".claude",
        label: "Claude Code profile",
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".cursor",
        label: "Cursor profile",
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".codeium\\windsurf",
        label: "Windsurf profile",
    },
    Candidate {
        base: "APPDATA",
        relative: "Claude",
        label: "Claude Desktop",
    },
    Candidate {
        base: "APPDATA",
        relative: "Cursor",
        label: "Cursor Desktop",
    },
    Candidate {
        base: "APPDATA",
        relative: "Codeium\\Windsurf",
        label: "Windsurf Desktop",
    },
    Candidate {
        base: "LOCALAPPDATA",
        relative: "Programs\\Ollama",
        label: "Ollama",
    },
    Candidate {
        base: "LOCALAPPDATA",
        relative: "Programs\\LM Studio",
        label: "LM Studio",
    },
    Candidate {
        base: "APPDATA",
        relative: "Code\\User\\globalStorage\\github.copilot",
        label: "GitHub Copilot storage",
    },
    Candidate {
        base: "APPDATA",
        relative: "Code\\User\\globalStorage\\github.copilot-chat",
        label: "GitHub Copilot Chat storage",
    },
    Candidate {
        base: "APPDATA",
        relative: "Claude\\claude_desktop_config.json",
        label: "Claude Desktop MCP config",
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".claude.json",
        label: "Claude Code MCP config",
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".cursor\\mcp.json",
        label: "Cursor MCP config",
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".codeium\\windsurf\\mcp_config.json",
        label: "Windsurf MCP config",
    },
];

const PROJECT_ROOTS: &[&str] = &[
    "source",
    "src",
    "code",
    "repos",
    "projects",
    "Documents\\GitHub",
    "Documents\\Repos",
    "Documents\\Projects",
    "Desktop",
];

fn choose_base<'a>(
    candidate: &Candidate,
    profile: Option<&'a str>,
    appdata: Option<&'a str>,
    local: Option<&'a str>,
) -> Option<&'a str> {
    match candidate.base {
        "USERPROFILE" => profile,
        "APPDATA" => appdata,
        "LOCALAPPDATA" => local,
        _ => None,
    }
}

#[rustbof::main]
fn main() {
    println!("AI development surface");
    println!("Presence only; configuration and session contents are not read.\n");

    let profile = environment("USERPROFILE").ok();
    let appdata = environment("APPDATA").ok();
    let local = environment("LOCALAPPDATA").ok();
    let mut found = 0usize;
    let mut mcp = 0usize;
    let mut projects = 0usize;

    for candidate in CANDIDATES {
        let Some(base) = choose_base(
            candidate,
            profile.as_deref(),
            appdata.as_deref(),
            local.as_deref(),
        ) else {
            continue;
        };
        let path = join(base, candidate.relative);
        if metadata(&path).is_ok() {
            println!("{} | {}", candidate.label, path);
            found += 1;
            if candidate.label.contains("MCP") {
                mcp += 1;
            }
        }
    }

    if let Some(profile) = profile.as_deref() {
        for root in PROJECT_ROOTS {
            let root_path = join(profile, root);
            let Ok(entries) = children(&root_path, 64) else {
                continue;
            };
            for entry in entries {
                if !entry.metadata.is_directory || entry.metadata.is_reparse_point {
                    continue;
                }
                for relative in [".mcp.json", ".cursor\\rules\\mcp.json"] {
                    let path = join(&entry.path, relative);
                    if metadata(&path).is_ok() {
                        println!("Project MCP config | {}", path);
                        found += 1;
                        mcp += 1;
                    }
                }
                projects += 1;
                if projects >= 256 {
                    break;
                }
            }
            if projects >= 256 {
                break;
            }
        }
    }

    println!(
        "\nArtifacts found: {} | MCP configs: {} | project directories examined: {}",
        found, mcp, projects
    );
}
