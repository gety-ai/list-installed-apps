use std::{
    collections::HashMap,
    env,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use plist::Value;
use rayon::prelude::*;

use crate::InstalledPackage;

fn build_io_pool() -> std::io::Result<rayon::ThreadPool> {
    let n = std::thread::available_parallelism()
        .map(|n| (n.get() / 2).clamp(2, 8))
        .unwrap_or(4);
    rayon::ThreadPoolBuilder::new()
        .num_threads(n)
        .build()
        .map_err(|e| std::io::Error::other(e.to_string()))
}

pub fn collect_installed_apps() -> std::io::Result<Vec<InstalledPackage>> {
    let mut app_dirs = vec![
        PathBuf::from("/Applications"),
        PathBuf::from("/System/Applications"),
    ];
    if let Ok(home) = env::var("HOME") {
        app_dirs.push(PathBuf::from(home).join("Applications"));
    }

    let pool = build_io_pool()?;

    // Run all three sources in parallel inside a bounded I/O pool
    let pkgs = pool.install(|| {
        let ((app_pkgs, pkgutil_pkgs), brew_pkgs) = rayon::join(
            || {
                rayon::join(
                    || harvest_app_dirs(&app_dirs),
                    harvest_pkgutil,
                )
            },
            harvest_homebrew,
        );

        let mut pkgs = app_pkgs;
        pkgs.extend(pkgutil_pkgs);
        pkgs.extend(brew_pkgs);
        pkgs
    });

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

// ---------------------------------------------------------------------------
// .app bundles
// ---------------------------------------------------------------------------

/// Collect all .app paths from directories, then parse plists in parallel
fn harvest_app_dirs(dirs: &[PathBuf]) -> Vec<InstalledPackage> {
    let paths: Vec<PathBuf> = dirs
        .iter()
        .flat_map(|dir| collect_app_paths(dir, 2))
        .collect();

    paths
        .par_iter()
        .filter_map(|path| parse_app_bundle(path))
        .collect()
}

/// Recursively collect .app bundle paths (lightweight readdir, no plist parsing)
fn collect_app_paths(dir: &Path, max_depth: u32) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return paths,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("app") {
            paths.push(path);
        } else if max_depth > 0 && path.is_dir() {
            paths.extend(collect_app_paths(&path, max_depth - 1));
        }
    }

    paths
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

// ---------------------------------------------------------------------------
// pkgutil
// ---------------------------------------------------------------------------

/// Collect packages installed via pkgutil, reading receipt plists in parallel
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

    let pkg_ids: Vec<&str> = stdout
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    pkg_ids
        .par_iter()
        .map(|pkg_id| {
            let receipt_path = receipts_dir.join(format!("{pkg_id}.plist"));
            let (version, install_location) = parse_receipt_plist(&receipt_path);

            InstalledPackage {
                name: pkg_id.to_string(),
                version,
                publisher: None,
                install_location,
                uninstall_string: None,
                key_path: format!("pkgutil:{pkg_id}"),
            }
        })
        .collect()
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

// ---------------------------------------------------------------------------
// Homebrew
// ---------------------------------------------------------------------------

/// Collect packages installed via Homebrew (formula + cask in parallel)
fn harvest_homebrew() -> Vec<InstalledPackage> {
    let brew_prefix = match find_brew_prefix() {
        Some(prefix) => prefix,
        None => return vec![],
    };
    let brew_cmd = PathBuf::from(&brew_prefix).join("bin/brew");

    let (formula_pkgs, cask_pkgs) = rayon::join(
        || harvest_brew_formulas(&brew_cmd, &brew_prefix),
        || harvest_brew_casks(&brew_cmd),
    );

    let mut pkgs = formula_pkgs;
    pkgs.extend(cask_pkgs);
    pkgs
}

fn harvest_brew_formulas(brew_cmd: &Path, brew_prefix: &str) -> Vec<InstalledPackage> {
    let output = match run_brew(brew_cmd, &["list", "--formula", "--versions"]) {
        Some(o) => o,
        None => return vec![],
    };

    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let name = parts.next()?;
            let version = parts.next().map(String::from);

            let install_location = {
                let ver = version.as_deref().unwrap_or("unknown");
                Some(format!("{brew_prefix}/Cellar/{name}/{ver}"))
            };

            Some(InstalledPackage {
                name: name.to_string(),
                version,
                publisher: None,
                install_location,
                uninstall_string: Some(format!("brew uninstall {name}")),
                key_path: format!("homebrew:formula:{name}"),
            })
        })
        .collect()
}

fn harvest_brew_casks(brew_cmd: &Path) -> Vec<InstalledPackage> {
    let output = match run_brew(brew_cmd, &["list", "--cask", "--versions"]) {
        Some(o) => o,
        None => return vec![],
    };

    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let name = parts.next()?;
            let version = parts.next().map(String::from);

            Some(InstalledPackage {
                name: name.to_string(),
                version,
                publisher: None,
                install_location: None, // Cask apps are in /Applications, covered by .app scan
                uninstall_string: Some(format!("brew uninstall --cask {name}")),
                key_path: format!("homebrew:cask:{name}"),
            })
        })
        .collect()
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
