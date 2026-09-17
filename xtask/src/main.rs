use std::collections::BTreeSet;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone)]
struct Bof {
    category: String,
    name: String,
    directory: PathBuf,
    description: String,
    arguments: Vec<String>,
    techniques: Vec<String>,
    output: Vec<String>,
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live below the repository root")
        .to_path_buf();
    let result = match env::args().nth(1).as_deref() {
        Some("build-all") => build_all(&root),
        Some("generate-assets") => generate_assets(&root),
        Some("check-assets") => check_assets(&root),
        Some("check-yara") => check_yara(&root),
        Some("check-release") => check_assets(&root).and_then(|_| check_yara(&root)),
        _ => Err(String::from(
            "usage: cargo run --manifest-path xtask/Cargo.toml -- <build-all|generate-assets|check-assets|check-yara|check-release>",
        )),
    };

    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn discover(root: &Path) -> Result<Vec<Bof>, String> {
    let bofs_root = root.join("bofs");
    let mut manifests = Vec::new();
    walk(&bofs_root, &mut manifests)?;
    manifests.sort();

    let mut bofs = Vec::new();
    for manifest in manifests {
        if manifest.file_name() != Some(OsStr::new("Cargo.toml")) {
            continue;
        }
        let directory = manifest
            .parent()
            .ok_or_else(|| format!("invalid manifest path: {}", manifest.display()))?
            .to_path_buf();
        let relative = directory
            .strip_prefix(&bofs_root)
            .map_err(|error| error.to_string())?;
        let category = relative
            .components()
            .next()
            .ok_or_else(|| format!("missing category: {}", directory.display()))?
            .as_os_str()
            .to_string_lossy()
            .to_string();
        let manifest_text = fs::read_to_string(&manifest)
            .map_err(|error| format!("{}: {error}", manifest.display()))?;
        let name = package_name(&manifest_text)
            .ok_or_else(|| format!("missing package name: {}", manifest.display()))?;
        let source_path = directory.join("src").join("lib.rs");
        let source = fs::read_to_string(&source_path).unwrap_or_default();
        let docs = parse_docs(&source);
        let output = output_literals(&source);
        let description = if docs.0 == "Rust Beacon Object File for Windows security research." {
            fallback_description(&name)
        } else {
            docs.0
        };
        bofs.push(Bof {
            category,
            name,
            directory,
            description,
            arguments: docs.1,
            techniques: docs.2,
            output,
        });
    }
    Ok(bofs)
}

fn walk(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries =
        fs::read_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if file_type.is_dir() {
            if !matches!(entry.file_name().to_str(), Some("target" | "out")) {
                walk(&path, files)?;
            }
        } else if entry.file_name() == "Cargo.toml" {
            files.push(path);
        }
    }
    Ok(())
}

fn package_name(manifest: &str) -> Option<String> {
    let mut package = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            package = trimmed == "[package]";
            continue;
        }
        if package && trimmed.starts_with("name") {
            return trimmed
                .split_once('=')
                .map(|(_, value)| value.trim().trim_matches('"').to_string());
        }
    }
    None
}

fn parse_docs(source: &str) -> (String, Vec<String>, Vec<String>) {
    let mut description = Vec::new();
    let mut arguments = Vec::new();
    let mut techniques = Vec::new();
    let mut section = "description";
    for line in source.lines() {
        let Some(text) = line.strip_prefix("//!") else {
            if !line.trim().is_empty() {
                break;
            }
            continue;
        };
        let text = text.trim();
        if text.starts_with("# ") {
            continue;
        }
        if text == "## Arguments" {
            section = "arguments";
            continue;
        }
        if text == "## MITRE ATT&CK" {
            section = "techniques";
            continue;
        }
        if text.starts_with("## ") {
            section = "other";
            continue;
        }
        if text.is_empty() {
            continue;
        }
        match section {
            "description" => description.push(text.trim_start_matches("- ").to_string()),
            "arguments" => push_doc_item(&mut arguments, text),
            "techniques" => push_doc_item(&mut techniques, text),
            _ => {}
        }
    }
    let description = if description.is_empty() {
        String::from("Rust Beacon Object File for Windows security research.")
    } else {
        description.join(" ")
    };
    (description, arguments, techniques)
}

fn push_doc_item(items: &mut Vec<String>, text: &str) {
    if let Some(item) = text.strip_prefix("- ") {
        items.push(item.to_string());
    } else if let Some(item) = items.last_mut() {
        item.push(' ');
        item.push_str(text);
    } else {
        items.push(text.to_string());
    }
}

fn fallback_description(name: &str) -> String {
    let description = match name {
        "arp" => "Lists the local ARP cache.",
        "env" => "Lists environment variables in the current process context.",
        "ipconfig" => "Lists local network adapter configuration.",
        "locale" => "Reads system locale, language, and country settings.",
        "netstat" => "Lists TCP and UDP connections with owning process identifiers.",
        "resources" => "Reads system memory and disk usage.",
        "routeprint" => "Lists the local IPv4 routing table.",
        "whoami" => "Reports the current user, groups, and token privileges.",
        "windowlist" => "Lists visible desktop windows and their titles.",
        "kernel" => {
            "Uses a supplied vulnerable-driver adapter for Windows kernel and physical-memory research actions."
        }
        _ => "Rust Beacon Object File for Windows security research.",
    };
    String::from(description)
}

fn output_literals(source: &str) -> Vec<String> {
    let mut results = Vec::new();
    for marker in ["println!", "eprintln!"] {
        let mut remaining = source;
        while let Some(index) = remaining.find(marker) {
            remaining = &remaining[index + marker.len()..];
            let Some(open) = remaining.find('"') else {
                break;
            };
            let bytes = remaining.as_bytes();
            let mut value = String::new();
            let mut escaped = false;
            let mut end = None;
            for (position, byte) in bytes.iter().enumerate().skip(open + 1) {
                if escaped {
                    match *byte {
                        b'n' => value.push('\n'),
                        b'r' => {}
                        b't' => value.push(' '),
                        b'\\' => value.push('\\'),
                        b'"' => value.push('"'),
                        other => value.push(other as char),
                    }
                    escaped = false;
                } else if *byte == b'\\' {
                    escaped = true;
                } else if *byte == b'"' {
                    end = Some(position + 1);
                    break;
                } else if byte.is_ascii() {
                    value.push(*byte as char);
                }
            }
            if let Some(end) = end {
                remaining = &remaining[end..];
            } else {
                break;
            }
            let value = value.trim().to_string();
            if value.len() >= 8
                && !value.starts_with("Usage:")
                && !value.starts_with("[X]")
                && !value.starts_with("[-]")
                && !value.to_ascii_lowercase().contains("failed")
                && !value.to_ascii_lowercase().contains("must be supplied")
                && !value.to_ascii_lowercase().contains("required")
                && !results.contains(&value)
            {
                results.push(value);
            }
        }
    }
    results.sort_by_key(|value| {
        let lower = value.to_ascii_lowercase();
        let preferred = [
            "inventory",
            "configuration",
            "status",
            "complete",
            "success",
            "created",
            "wrote",
            "removed",
            "enumerat",
        ]
        .iter()
        .any(|word| lower.contains(word));
        (!preferred, usize::MAX - value.len())
    });
    results.truncate(3);
    results
}

fn redact_format_fields(value: &str) -> String {
    let mut result = String::new();
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'{' {
            if index + 1 < bytes.len() && bytes[index + 1] == b'{' {
                result.push('{');
                index += 2;
                continue;
            }
            if let Some(close) = bytes[index + 1..].iter().position(|byte| *byte == b'}') {
                result.push_str("<value>");
                index += close + 2;
                continue;
            }
        }
        result.push(bytes[index] as char);
        index += 1;
    }
    result
}

fn static_format_segments(value: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'{' {
            if index + 1 < bytes.len() && bytes[index + 1] == b'{' {
                current.push('{');
                index += 2;
                continue;
            }
            if let Some(close) = bytes[index + 1..].iter().position(|byte| *byte == b'}') {
                if !current.is_empty() {
                    segments.push(core::mem::take(&mut current));
                }
                index += close + 2;
                continue;
            }
        }
        if bytes[index] == b'}' && index + 1 < bytes.len() && bytes[index + 1] == b'}' {
            current.push('}');
            index += 2;
            continue;
        }
        current.push(bytes[index] as char);
        index += 1;
    }
    if !current.is_empty() {
        segments.push(current);
    }
    segments
}

fn build_all(root: &Path) -> Result<(), String> {
    let bofs = discover(root)?;
    let catalog_target = root.join("target").join("catalog");
    let kernel_target = root.join("target").join("kernel");
    let mut failures = Vec::new();

    build_workspace(root, &catalog_target)?;
    for bof in bofs.iter().filter(|bof| bof.category != "kernel") {
        println!("[link] {}/{}", bof.category, bof.name);
        if let Err(error) = link_one(bof, &catalog_target) {
            failures.push(format!("{}/{}: {error}", bof.category, bof.name));
        }
    }

    for bof in bofs.iter().filter(|bof| bof.category == "kernel") {
        println!("[build] {}/{}", bof.category, bof.name);
        if let Err(error) = build_one(bof, &kernel_target) {
            failures.push(format!("{}/{}: {error}", bof.category, bof.name));
        }
    }

    if failures.is_empty() {
        println!("Built and linked every discovered BOF.");
        Ok(())
    } else {
        Err(format!("failed BOFs: {}", failures.join(", ")))
    }
}

fn build_workspace(root: &Path, target_directory: &Path) -> Result<(), String> {
    let toolchain = nearest_toolchain(&root.join("bofs"))?;
    let build = Command::new("cargo")
        .arg(format!("+{toolchain}"))
        .args([
            "-Z",
            "build-std=core,alloc,panic_abort,compiler_builtins",
            "-Z",
            "build-std-features=panic_immediate_abort,compiler-builtins-mem",
            "build",
            "--workspace",
            "--offline",
            "--quiet",
            "--release",
            "--target",
            "x86_64-pc-windows-gnu",
        ])
        .env("CARGO_TARGET_DIR", target_directory)
        .env(
            "RUSTFLAGS",
            "-Csymbol-mangling-version=v0 -Zlocation-detail=none -Zunstable-options -Zfunction-sections=yes -Cpanic=abort",
        )
        .current_dir(root)
        .status()
        .map_err(|error| format!("could not start Cargo: {error}"))?;
    if build.success() {
        Ok(())
    } else {
        Err(String::from("workspace Cargo build failed"))
    }
}

fn build_one(bof: &Bof, target_directory: &Path) -> Result<(), String> {
    let toolchain = nearest_toolchain(&bof.directory)?;

    let build = Command::new("cargo")
        .arg(format!("+{toolchain}"))
        .args([
            "-Z",
            "build-std=core,alloc,panic_abort,compiler_builtins",
            "-Z",
            "build-std-features=panic_immediate_abort",
            "build",
            "--offline",
            "--release",
            "--target",
            "x86_64-pc-windows-gnu",
        ])
        .env("CARGO_TARGET_DIR", target_directory)
        .env(
            "RUSTFLAGS",
            "-Csymbol-mangling-version=v0 -Zlocation-detail=none -Zunstable-options -Zfunction-sections=yes -Cpanic=abort",
        )
        .current_dir(&bof.directory)
        .status()
        .map_err(|error| format!("could not start Cargo: {error}"))?;
    if !build.success() {
        return Err(String::from("Cargo build failed"));
    }

    link_one(bof, target_directory)
}

fn link_one(bof: &Bof, target_directory: &Path) -> Result<(), String> {
    let makefile_path = bof.directory.join("Makefile.toml");
    let makefile = fs::read_to_string(&makefile_path)
        .map_err(|error| format!("{}: {error}", makefile_path.display()))?;
    let name = make_value(&makefile, "NAME")
        .ok_or_else(|| format!("{} has no NAME", makefile_path.display()))?;
    let libraries = make_value(&makefile, "LIBS")
        .ok_or_else(|| format!("{} has no LIBS", makefile_path.display()))?;

    let output_directory = bof.directory.join("out");
    fs::create_dir_all(&output_directory)
        .map_err(|error| format!("{}: {error}", output_directory.display()))?;
    let archive = target_directory
        .join("x86_64-pc-windows-gnu")
        .join("release")
        .join(format!("lib{}.a", name.replace('-', "_")));
    if !archive.is_file() {
        return Err(format!("missing static library: {}", archive.display()));
    }
    let output = output_directory.join(format!("{name}.x64.o"));
    let linker = env::var("BOFLINK").unwrap_or_else(|_| String::from("boflink"));
    let mut command = Command::new(&linker);
    command.arg("--mingw64");
    for library in libraries.split_whitespace() {
        command.arg(library);
    }
    if makefile.contains("--warn-unresolved-symbols") {
        command.arg("--warn-unresolved-symbols");
    }
    let link = command
        .args(["--gc-sections", "--entry=go"])
        .arg(&archive)
        .arg("-o")
        .arg(&output)
        .current_dir(&bof.directory)
        .status()
        .map_err(|error| format!("could not start {linker}: {error}"))?;
    if link.success() {
        Ok(())
    } else {
        Err(String::from("boflink failed"))
    }
}

fn nearest_toolchain(directory: &Path) -> Result<String, String> {
    for parent in directory.ancestors() {
        let path = parent.join("rust-toolchain.toml");
        if path.is_file() {
            let contents = fs::read_to_string(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            return make_value(&contents, "channel")
                .ok_or_else(|| format!("{} has no channel", path.display()));
        }
    }
    Err(format!(
        "no rust-toolchain.toml found above {}",
        directory.display()
    ))
}

fn make_value(makefile: &str, key: &str) -> Option<String> {
    makefile.lines().find_map(|line| {
        let (left, right) = line.split_once('=')?;
        if left.trim() == key {
            Some(right.trim().trim_matches('"').to_string())
        } else {
            None
        }
    })
}

fn generate_assets(root: &Path) -> Result<(), String> {
    let bofs = discover(root)?;
    for bof in &bofs {
        if bof.name != "kernel" {
            fs::write(bof.directory.join("README.md"), readme(bof))
                .map_err(|error| format!("{}: {error}", bof.directory.display()))?;
            fs::write(bof.directory.join(format!("{}.yar", bof.name)), yara(bof))
                .map_err(|error| format!("{}: {error}", bof.directory.display()))?;
        }
    }
    update_index(root, &bofs)?;
    println!("Generated {} BOF pages and YARA rules.", bofs.len());
    Ok(())
}

fn readme(bof: &Bof) -> String {
    let techniques = if bof.techniques.is_empty() {
        String::from("- Not mapped")
    } else {
        bof.techniques
            .iter()
            .map(|item| format!("- {item}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let arguments = if bof.arguments.is_empty()
        || bof
            .arguments
            .iter()
            .any(|item| item.eq_ignore_ascii_case("None."))
    {
        String::from("No arguments.")
    } else {
        bof.arguments
            .iter()
            .map(|item| format!("- {item}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let no_arguments = arguments == "No arguments.";
    let command = if no_arguments {
        format!("inline-execute /path/to/{}.x64.o", bof.name)
    } else {
        format!("{} <packed-arguments>", bof.name)
    };
    let argument_note = if no_arguments {
        String::new()
    } else {
        String::from(
            "\nThe command shape above assumes a small Aggressor Script wrapper. Pack the values in the listed order with `bof_pack`; this repository does not ship a CNA wrapper.\n",
        )
    };
    let sample = if bof.output.is_empty() {
        String::from("<target-specific output redacted>")
    } else {
        bof.output
            .iter()
            .map(|value| redact_format_fields(value))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let relative = bof
        .directory
        .components()
        .rev()
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<PathBuf>();
    format!(
        "# {}\n\n{}\n\n## MITRE ATT&CK\n\n{}\n\n## Arguments\n\n{}\n\n## Build\n\n```text\ncd {}\ncargo make\n```\n\n## Example\n\n```text\nbeacon> {}\n{}\n```\n{}",
        bof.name,
        bof.description,
        techniques,
        arguments,
        relative.to_string_lossy().replace('\\', "/"),
        command,
        sample,
        argument_note
    )
}

fn yara(bof: &Bof) -> String {
    let identifier = format!("Armory_BOF_{}_{}", bof.category, bof.name)
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    let capability = bof
        .output
        .iter()
        .flat_map(|value| static_format_segments(value))
        .filter(|value| {
            value
                .chars()
                .filter(|character| character.is_alphanumeric())
                .count()
                >= 8
        })
        .max_by_key(|value| value.len())
        .unwrap_or_else(|| String::from("go"));
    format!(
        "rule {identifier}\n{{\n    meta:\n        description = \"Compiled Rust BOF: {}\"\n        author = \"memN0ps\"\n\n    strings:\n        $crate = \"{}\" ascii\n        $capability = \"{}\" ascii\n\n    condition:\n        uint16(0) == 0x8664 and all of them\n}}\n",
        escape_yara(&bof.name),
        escape_yara(&bof.name.replace('-', "_")),
        escape_yara(&capability)
    )
}

fn escape_yara(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn update_index(root: &Path, bofs: &[Bof]) -> Result<(), String> {
    let readme_path = root.join("README.md");
    let mut readme = fs::read_to_string(&readme_path).map_err(|error| error.to_string())?;
    let start = "<!-- BOF_INDEX_START -->";
    let end = "<!-- BOF_INDEX_END -->";
    let index = index_section(root, bofs)?;

    if let (Some(left), Some(right)) = (readme.find(start), readme.find(end)) {
        let section_start = readme[..left]
            .rfind("## Complete BOF Index")
            .unwrap_or(left);
        let section_end = right + end.len();
        readme.replace_range(section_start..section_end, &index);
    } else {
        let insertion = readme
            .find("## Building")
            .ok_or_else(|| String::from("README is missing the Building heading"))?;
        readme.insert_str(insertion, &format!("{index}\n\n"));
    }
    fs::write(readme_path, readme).map_err(|error| error.to_string())
}

fn index_section(root: &Path, bofs: &[Bof]) -> Result<String, String> {
    let mut index = String::from(
        "## Complete BOF Index\n\nThis is the complete source index. Each link contains the TTP, argument order, build command, example command, redacted output shape, and YARA rule.\n\n<!-- BOF_INDEX_START -->\n",
    );
    for category in ["sa", "remote", "injection", "kerbeus", "kernel"] {
        let title = match category {
            "sa" => "Situational Awareness",
            "remote" => "Remote Operations",
            "injection" => "Injection",
            "kerbeus" => "Kerberos",
            _ => "Kernel",
        };
        index.push_str(&format!(
            "\n### {title}\n\n| BOF | What it does |\n|---|---|\n"
        ));
        for bof in bofs.iter().filter(|bof| bof.category == category) {
            let link = bof
                .directory
                .strip_prefix(root)
                .map_err(|error| error.to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            let description = bof.description.replace('|', "\\|");
            index.push_str(&format!(
                "| [`{}`](./{link}/) | {description} |\n",
                bof.name
            ));
        }
    }
    index.push_str("\n<!-- BOF_INDEX_END -->");
    Ok(index)
}

fn check_assets(root: &Path) -> Result<(), String> {
    let bofs = discover(root)?;
    let root_readme =
        fs::read_to_string(root.join("README.md")).map_err(|error| error.to_string())?;
    let mut failures = Vec::new();
    let mut names = BTreeSet::new();

    if bofs.is_empty() {
        failures.push(String::from("no BOF manifests were discovered"));
    }

    for bof in &bofs {
        let identity = format!("{}/{}", bof.category, bof.name);
        if !names.insert(bof.name.to_ascii_lowercase()) {
            failures.push(format!("{identity}: duplicate package name"));
        }
        if bof.directory.file_name() != Some(OsStr::new(&bof.name)) {
            failures.push(format!("{identity}: directory and package names differ"));
        }

        let source_path = bof.directory.join("src").join("lib.rs");
        let source = match fs::read_to_string(&source_path) {
            Ok(source) => source,
            Err(error) => {
                failures.push(format!("{}: {error}", source_path.display()));
                continue;
            }
        };
        if !source.trim_start().starts_with("//!") {
            failures.push(format!("{identity}: lib.rs has no crate documentation"));
        }
        if !source.contains("//! ## Arguments") {
            failures.push(format!("{identity}: crate docs have no Arguments section"));
        }
        if !source.contains("//! ## MITRE ATT&CK") || bof.techniques.is_empty() {
            failures.push(format!(
                "{identity}: crate docs have no MITRE ATT&CK mapping"
            ));
        }
        if bof
            .techniques
            .iter()
            .any(|technique| technique.eq_ignore_ascii_case("Not mapped"))
        {
            failures.push(format!("{identity}: MITRE ATT&CK is still unmapped"));
        }
        if bof.description == "Rust Beacon Object File for Windows security research." {
            failures.push(format!("{identity}: crate description is still generic"));
        }

        let manifest_path = bof.directory.join("Cargo.toml");
        let manifest = fs::read_to_string(&manifest_path)
            .map_err(|error| format!("{}: {error}", manifest_path.display()))?;
        if !manifest.contains("publish = false") {
            failures.push(format!(
                "{identity}: Cargo package is not marked publish=false"
            ));
        }
        if !manifest.contains("crate-type = [\"staticlib\"]") {
            failures.push(format!("{identity}: Cargo crate type is not staticlib"));
        }
        for line in manifest.lines().filter(|line| line.contains("path =")) {
            if !line.contains("rustbof") {
                failures.push(format!(
                    "{identity}: shared path dependency is not allowed: {}",
                    line.trim()
                ));
            }
        }

        let makefile_path = bof.directory.join("Makefile.toml");
        let makefile = match fs::read_to_string(&makefile_path) {
            Ok(makefile) => makefile,
            Err(error) => {
                failures.push(format!("{}: {error}", makefile_path.display()));
                continue;
            }
        };
        if make_value(&makefile, "NAME").as_deref() != Some(bof.name.as_str()) {
            failures.push(format!(
                "{identity}: Makefile NAME does not match package name"
            ));
        }
        if make_value(&makefile, "CARGO_TARGET_DIR").as_deref() != Some("target") {
            failures.push(format!(
                "{identity}: Makefile must keep an independent local Cargo target directory"
            ));
        }

        let readme_path = bof.directory.join("README.md");
        match fs::read_to_string(&readme_path) {
            Ok(contents)
                if bof.name == "kernel"
                    && contents.contains("## Actions")
                    && contents.contains("## Windows protections")
                    && contents.contains("## Run")
                    && contents.contains("credentials read")
                    && contents.contains("callback image disable") => {}
            Ok(contents) if bof.name != "kernel" && contents == readme(bof) => {}
            Ok(_) if bof.name == "kernel" => {
                failures.push(format!("{identity}: hand-written README is incomplete"))
            }
            Ok(_) => failures.push(format!("{identity}: generated README is stale")),
            Err(error) => failures.push(format!("{}: {error}", readme_path.display())),
        }

        let yara_path = bof.directory.join(format!("{}.yar", bof.name));
        if bof.name == "kernel" {
            if !yara_path.is_file() {
                failures.push(format!("{identity}: missing hand-written YARA rule"));
            }
        } else {
            match fs::read_to_string(&yara_path) {
                Ok(contents) if contents == yara(bof) => {}
                Ok(_) => failures.push(format!("{identity}: generated YARA is stale")),
                Err(error) => failures.push(format!("{}: {error}", yara_path.display())),
            }
        }

        let link = bof
            .directory
            .strip_prefix(root)
            .map_err(|error| error.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        if !root_readme.contains(&format!("(./{link}/)")) {
            failures.push(format!("{identity}: missing root index link"));
        }
    }

    let expected_index = index_section(root, &bofs)?;
    let start = root_readme
        .find("## Complete BOF Index")
        .ok_or_else(|| String::from("README is missing the complete BOF index"))?;
    let end_marker = "<!-- BOF_INDEX_END -->";
    let end = root_readme[start..]
        .find(end_marker)
        .map(|offset| start + offset + end_marker.len())
        .ok_or_else(|| String::from("README BOF index has no end marker"))?;
    if root_readme[start..end] != expected_index {
        failures.push(String::from("root README BOF index is stale"));
    }

    check_tracked_files(root, &mut failures)?;

    if failures.is_empty() {
        println!(
            "Checked {} independent BOFs: crate docs, MITRE mappings, manifests, build names, README files, YARA files, root index, and tracked-file policy all match.",
            bofs.len()
        );
        Ok(())
    } else {
        Err(format!("release asset failures: {}", failures.join("; ")))
    }
}

fn check_tracked_files(root: &Path, failures: &mut Vec<String>) -> Result<(), String> {
    let output = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(root)
        .output()
        .map_err(|error| format!("could not start git: {error}"))?;
    if !output.status.success() {
        return Err(String::from("git ls-files failed"));
    }

    let paths = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty());
    for bytes in paths {
        let relative = String::from_utf8(bytes.to_vec())
            .map_err(|_| String::from("git returned a non-UTF-8 path"))?;
        let lower = relative.to_ascii_lowercase();
        if lower.ends_with("cargo.lock")
            || lower.ends_with(".o")
            || lower.ends_with(".bin")
            || lower.ends_with(".py")
            || lower.contains("/target/")
            || lower.contains("/out/")
        {
            failures.push(format!(
                "tracked release artifact is not allowed: {relative}"
            ));
        }

        let extension = Path::new(&relative)
            .extension()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        let text_file = matches!(
            extension,
            "rs" | "md" | "toml" | "yar" | "yara" | "txt" | "c" | "h" | "asm" | "s"
        ) || matches!(relative.as_str(), "README.md" | "LICENSE" | ".gitignore");
        if !text_file {
            continue;
        }

        let path = root.join(&relative);
        if !path.is_file() {
            continue;
        }
        let contents =
            fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        for character in [
            '\u{2018}', '\u{2019}', '\u{201c}', '\u{201d}', '\u{2013}', '\u{2014}',
        ] {
            if contents.contains(character) {
                failures.push(format!(
                    "non-ASCII quote or dash U+{:04X}: {relative}",
                    character as u32
                ));
            }
        }

        let windows_user_prefix = ["C:", "\\Users\\"].concat();
        let mut remainder = contents.as_str();
        while let Some(offset) = remainder.find(&windows_user_prefix) {
            let value = &remainder[offset + windows_user_prefix.len()..];
            let user = value
                .split(['\\', '/', ' ', '\n', '\r', '`'])
                .next()
                .unwrap_or_default();
            if !user.is_empty()
                && !matches!(
                    user.to_ascii_lowercase().as_str(),
                    "user" | "public" | "default" | "<user>" | "<username>"
                )
            {
                failures.push(format!("machine-specific Windows profile path: {relative}"));
                break;
            }
            remainder = value;
        }
    }
    Ok(())
}

fn check_yara(root: &Path) -> Result<(), String> {
    let bofs = discover(root)?;
    let output_directory = root.join("target").join("yara-check");
    fs::create_dir_all(&output_directory)
        .map_err(|error| format!("{}: {error}", output_directory.display()))?;
    let mut failures = Vec::new();

    for (index, bof) in bofs.iter().enumerate() {
        let makefile_path = bof.directory.join("Makefile.toml");
        let makefile = fs::read_to_string(&makefile_path)
            .map_err(|error| format!("{}: {error}", makefile_path.display()))?;
        let object_name = make_value(&makefile, "NAME")
            .ok_or_else(|| format!("{} has no NAME", makefile_path.display()))?;
        let object = bof
            .directory
            .join("out")
            .join(format!("{object_name}.x64.o"));
        let rule = bof.directory.join(format!("{}.yar", bof.name));
        let compiled = output_directory.join(format!("{}-{index}.yarc", bof.category));
        let identity = format!("{}/{}", bof.category, bof.name);

        if !object.is_file() {
            failures.push(format!("{identity}: missing linked object"));
            continue;
        }
        if !rule.is_file() {
            failures.push(format!("{identity}: missing YARA rule"));
            continue;
        }

        match Command::new("yarac").arg(&rule).arg(&compiled).output() {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                failures.push(format!(
                    "{identity}: YARA compile failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
                continue;
            }
            Err(error) => return Err(format!("could not start yarac: {error}")),
        }

        let positive = Command::new("yara")
            .arg("-C")
            .arg(&compiled)
            .arg(&object)
            .output()
            .map_err(|error| format!("could not start yara: {error}"))?;
        if !positive.status.success() || positive.stdout.is_empty() {
            failures.push(format!("{identity}: YARA did not match its linked object"));
        }

        let negative = bofs
            .iter()
            .find(|candidate| candidate.name != bof.name)
            .and_then(|candidate| {
                let makefile =
                    fs::read_to_string(candidate.directory.join("Makefile.toml")).ok()?;
                let name = make_value(&makefile, "NAME")?;
                Some(
                    candidate
                        .directory
                        .join("out")
                        .join(format!("{name}.x64.o")),
                )
            });
        if let Some(negative) = negative.filter(|path| path.is_file()) {
            let result = Command::new("yara")
                .arg("-C")
                .arg(&compiled)
                .arg(&negative)
                .output()
                .map_err(|error| format!("could not start yara: {error}"))?;
            if !result.status.success() {
                failures.push(format!("{identity}: YARA negative scan failed"));
            } else if !result.stdout.is_empty() {
                failures.push(format!(
                    "{identity}: YARA matched unrelated object {}",
                    negative.display()
                ));
            }
        }
    }

    if failures.is_empty() {
        println!(
            "Compiled {} YARA rules; every rule matched its linked object and rejected a same-toolchain BOF negative.",
            bofs.len()
        );
        Ok(())
    } else {
        Err(format!("YARA failures: {}", failures.join("; ")))
    }
}
