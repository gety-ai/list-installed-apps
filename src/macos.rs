use std::{
    collections::HashMap,
    env,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use plist::Value;

use crate::InstalledPackage;

pub fn collect_installed_apps() -> std::io::Result<Vec<InstalledPackage>> {
    let mut pkgs = Vec::new();

    // 1. Scan .app bundles from well-known directories
    let mut app_dirs = vec![
        PathBuf::from("/Applications"),
        PathBuf::from("/System/Applications"),
    ];
    if let Ok(home) = env::var("HOME") {
        app_dirs.push(PathBuf::from(home).join("Applications"));
    }

    for dir in &app_dirs {
        pkgs.extend(harvest_app_dir(dir, 2));
    }

    // 2. pkgutil packages
    pkgs.extend(harvest_pkgutil());

    // 3. Homebrew
    pkgs.extend(harvest_homebrew());

    // Dedup by (name, version)
    let mut seen = HashMap::new();
    for pkg in pkgs {
        match seen.get_mut(&(pkg.name.clone(), pkg.version.clone())) {
            None => {
                seen.insert((pkg.name.clone(), pkg.version.clone()), pkg);
            }
            Some(existing) => {
                if existing.install_location.is_none() {
                    *existing = pkg;
                }
            }
        }
    }

    Ok(seen.into_values().collect())
}

/// Recursively scan a directory for .app bundles (up to `max_depth` levels of nesting)
fn harvest_app_dir(dir: &Path, max_depth: u32) -> Vec<InstalledPackage> {
    let mut pkgs = Vec::new();

    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return pkgs,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("app") {
            if let Some(pkg) = parse_app_bundle(&path) {
                pkgs.push(pkg);
            }
        } else if max_depth > 0 && path.is_dir() {
            // Recurse into subdirectories (e.g., Utilities/)
            pkgs.extend(harvest_app_dir(&path, max_depth - 1));
        }
    }

    pkgs
}

/// Parse an .app bundle's Info.plist to extract metadata
fn parse_app_bundle(app_path: &Path) -> Option<InstalledPackage> {
    let plist_path = app_path.join("Contents/Info.plist");
    let dict = Value::from_file(&plist_path).ok()?.into_dictionary()?;

    let name = dict
        .get("CFBundleDisplayName")
        .or_else(|| dict.get("CFBundleName"))
        .and_then(|v| v.as_string())
        .map(String::from)
        .unwrap_or_else(|| {
            app_path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default()
        });

    if name.is_empty() {
        return None;
    }

    let version = dict
        .get("CFBundleShortVersionString")
        .or_else(|| dict.get("CFBundleVersion"))
        .and_then(|v| v.as_string())
        .map(String::from);

    let publisher = dict
        .get("NSHumanReadableCopyright")
        .and_then(|v| v.as_string())
        .map(String::from);

    let key_path = dict
        .get("CFBundleIdentifier")
        .and_then(|v| v.as_string())
        .map(String::from)
        .unwrap_or_else(|| app_path.to_string_lossy().to_string());

    Some(InstalledPackage {
        name,
        version,
        publisher,
        install_location: Some(app_path.to_string_lossy().to_string()),
        uninstall_string: None,
        key_path,
    })
}

/// Collect packages installed via pkgutil by reading receipt plists
fn harvest_pkgutil() -> Vec<InstalledPackage> {
    let output = match Command::new("pkgutil").arg("--pkgs").output() {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            log::warn!(
                "pkgutil --pkgs failed: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            return vec![];
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return vec![],
        Err(e) => {
            log::warn!("Failed to run pkgutil: {e}");
            return vec![];
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let receipts_dir = Path::new("/var/db/receipts");
    let mut pkgs = Vec::new();

    for pkg_id in stdout.lines() {
        let pkg_id = pkg_id.trim();
        if pkg_id.is_empty() {
            continue;
        }

        let receipt_path = receipts_dir.join(format!("{pkg_id}.plist"));
        let (version, install_location) = parse_receipt_plist(&receipt_path);

        pkgs.push(InstalledPackage {
            name: pkg_id.to_string(),
            version,
            publisher: None,
            install_location,
            uninstall_string: None,
            key_path: format!("pkgutil:{pkg_id}"),
        });
    }

    pkgs
}

/// Parse a pkgutil receipt plist for version and install location
fn parse_receipt_plist(path: &Path) -> (Option<String>, Option<String>) {
    let val = match Value::from_file(path) {
        Ok(v) => v,
        Err(_) => return (None, None),
    };

    let dict = match val.into_dictionary() {
        Some(d) => d,
        None => return (None, None),
    };

    let version = dict
        .get("PackageVersion")
        .and_then(|v| v.as_string())
        .map(String::from);

    let location = dict
        .get("InstallPrefixPath")
        .and_then(|v| v.as_string())
        .filter(|s| !s.is_empty() && *s != "/")
        .map(String::from);

    (version, location)
}

/// Collect packages installed via Homebrew
fn harvest_homebrew() -> Vec<InstalledPackage> {
    let mut pkgs = Vec::new();

    let brew_prefix = match find_brew_prefix() {
        Some(prefix) => prefix,
        None => return pkgs,
    };
    let brew_cmd = PathBuf::from(&brew_prefix).join("bin/brew");

    // Formulas (CLI tools)
    if let Some(output) = run_brew(&brew_cmd, &["list", "--formula", "--versions"]) {
        for line in output.lines() {
            let mut parts = line.split_whitespace();
            let name = match parts.next() {
                Some(n) => n,
                None => continue,
            };
            let version = parts.next().map(String::from);

            let install_location = {
                let ver = version.as_deref().unwrap_or("unknown");
                Some(format!("{brew_prefix}/Cellar/{name}/{ver}"))
            };

            pkgs.push(InstalledPackage {
                name: name.to_string(),
                version,
                publisher: None,
                install_location,
                uninstall_string: Some(format!("brew uninstall {name}")),
                key_path: format!("homebrew:formula:{name}"),
            });
        }
    }

    // Casks (GUI apps — .app bundles already covered by app dir scan)
    if let Some(output) = run_brew(&brew_cmd, &["list", "--cask", "--versions"]) {
        for line in output.lines() {
            let mut parts = line.split_whitespace();
            let name = match parts.next() {
                Some(n) => n,
                None => continue,
            };
            let version = parts.next().map(String::from);

            pkgs.push(InstalledPackage {
                name: name.to_string(),
                version,
                publisher: None,
                install_location: None, // Cask apps are in /Applications, covered by .app scan
                uninstall_string: Some(format!("brew uninstall --cask {name}")),
                key_path: format!("homebrew:cask:{name}"),
            });
        }
    }

    pkgs
}

/// Find the Homebrew prefix by checking known locations
fn find_brew_prefix() -> Option<String> {
    if let Ok(prefix) = env::var("HOMEBREW_PREFIX") {
        if PathBuf::from(&prefix).join("bin/brew").exists() {
            return Some(prefix);
        }
    }

    for candidate in ["/opt/homebrew", "/usr/local"] {
        if PathBuf::from(candidate).join("bin/brew").exists() {
            return Some(candidate.to_string());
        }
    }

    None
}

/// Run a brew command and return stdout on success
fn run_brew(brew_cmd: &Path, args: &[&str]) -> Option<String> {
    match Command::new(brew_cmd).args(args).output() {
        Ok(o) if o.status.success() => Some(String::from_utf8_lossy(&o.stdout).to_string()),
        Ok(o) => {
            log::warn!(
                "brew {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&o.stderr)
            );
            None
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            log::warn!("Failed to run brew: {e}");
            None
        }
    }
}
