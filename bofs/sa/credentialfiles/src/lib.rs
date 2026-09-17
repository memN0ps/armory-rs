//! # Developer Credential File Discovery BOF
//!
//! Reports the presence and size of common developer, cloud, CI/CD, package,
//! container, and SSH credential files for the current user. It never reads or
//! prints file contents.
//!
//! ## MITRE ATT&CK
//! - T1552.001 - Unsecured Credentials: Credentials In Files
//! - T1552.004 - Unsecured Credentials: Private Keys
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
    credential: bool,
}

const CANDIDATES: &[Candidate] = &[
    Candidate {
        base: "USERPROFILE",
        relative: ".aws\\credentials",
        label: "AWS credentials",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".aws\\config",
        label: "AWS config",
        credential: false,
    },
    Candidate {
        base: "APPDATA",
        relative: "gcloud\\application_default_credentials.json",
        label: "Google application default credentials",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".config\\gcloud\\application_default_credentials.json",
        label: "Google application default credentials",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".kube\\config",
        label: "Kubernetes config",
        credential: true,
    },
    Candidate {
        base: "APPDATA",
        relative: "terraform.d\\credentials.tfrc.json",
        label: "Terraform credentials",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".terraform.d\\credentials.tfrc.json",
        label: "Terraform credentials",
        credential: true,
    },
    Candidate {
        base: "APPDATA",
        relative: "GitHub CLI\\hosts.yml",
        label: "GitHub CLI auth",
        credential: true,
    },
    Candidate {
        base: "APPDATA",
        relative: "glab-cli\\config.yml",
        label: "GitLab CLI auth",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".config\\glab-cli\\config.yml",
        label: "GitLab CLI auth",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".npmrc",
        label: "npm config",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".pypirc",
        label: "Python package index config",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".docker\\config.json",
        label: "Docker config",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".cargo\\credentials.toml",
        label: "Cargo credentials",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".cargo\\credentials",
        label: "Cargo legacy credentials",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".m2\\settings.xml",
        label: "Maven settings",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".gradle\\gradle.properties",
        label: "Gradle properties",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".gem\\credentials",
        label: "RubyGems credentials",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".git-credentials",
        label: "Git credential store",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".gitconfig",
        label: "Git config",
        credential: false,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".netrc",
        label: "netrc",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: "_netrc",
        label: "Windows netrc",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".config\\containers\\auth.json",
        label: "Container auth",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".vault-token",
        label: "Vault token",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".ssh\\config",
        label: "SSH config",
        credential: false,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".ssh\\id_rsa",
        label: "SSH private key",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".ssh\\id_ed25519",
        label: "SSH private key",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".ssh\\id_ecdsa",
        label: "SSH private key",
        credential: true,
    },
    Candidate {
        base: "USERPROFILE",
        relative: ".ssh\\identity",
        label: "SSH private key",
        credential: true,
    },
];

#[rustbof::main]
fn main() {
    println!("Developer credential file discovery");
    println!("Presence and size only; file contents are not read.\n");

    let profile = environment("USERPROFILE").ok();
    let appdata = environment("APPDATA").ok();
    let mut credentials = 0usize;
    let mut configuration = 0usize;
    let mut errors = 0usize;

    for candidate in CANDIDATES {
        let base = if candidate.base == "USERPROFILE" {
            profile.as_deref()
        } else {
            appdata.as_deref()
        };
        let Some(base) = base else {
            errors += 1;
            continue;
        };
        let path = join(base, candidate.relative);
        match metadata(&path) {
            Ok(details) if !details.is_directory => {
                println!(
                    "{} | {} | {} bytes | {}",
                    if candidate.credential {
                        "credential"
                    } else {
                        "config"
                    },
                    candidate.label,
                    details.size,
                    path
                );
                if candidate.credential {
                    credentials += 1;
                } else {
                    configuration += 1;
                }
            }
            Ok(_) | Err(2) | Err(3) => {}
            Err(_) => errors += 1,
        }
    }

    if let Some(profile) = profile.as_deref() {
        let ssh = join(profile, ".ssh");
        if let Ok(entries) = children(&ssh, 64) {
            let mut pem = 0usize;
            for entry in entries {
                if !entry.metadata.is_directory
                    && entry.name.to_ascii_lowercase().ends_with(".pem")
                    && pem < 8
                {
                    println!(
                        "credential | SSH PEM candidate | {} bytes | {}",
                        entry.metadata.size, entry.path
                    );
                    credentials += 1;
                    pem += 1;
                }
            }
        }
    }

    println!(
        "\nCredential candidates: {} | configuration files: {} | access errors: {}",
        credentials, configuration, errors
    );
}
