use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use normalize_path::NormalizePath;
use serde::Serialize;
use windows::core::HSTRING;
use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows_registry::{Key, CURRENT_USER, LOCAL_MACHINE};

pub mod prelude;

#[derive(Debug, Serialize)]
pub struct InstalledPackage {
    name: String,
    version: Option<String>,
    publisher: Option<String>,
    install_location: Option<String>,
    uninstall_string: Option<String>,
    key_path: String,
}

pub trait InstalledPkgsExt {
    fn collect_installed_dir(self) -> Vec<PathBuf>;
}

impl InstalledPkgsExt for Vec<InstalledPackage> {
    fn collect_installed_dir(self) -> Vec<PathBuf> {
        collect_installed_dir(self)
    }
}

/// Helper – pull `DisplayName` entries from one `...\\Uninstall` hive
fn harvest_uninstall_hive(root: &Key, key_path: &str) -> Vec<InstalledPackage> {
    let mut pkgs = Vec::new();

    let keys = match root.keys() {
        Ok(keys) => keys,
        Err(e) => {
            log::error!("Error opening keys: {e}");
            return pkgs;
        }
    };

    for sk in keys {
        if let Ok(sub) = root.open(&sk) {
            let name = sub.get_string("DisplayName").ok();

            if let Some(display_name) = name {
                pkgs.push(InstalledPackage {
                    name: display_name,
                    version: sub.get_string("DisplayVersion").ok(),
                    publisher: sub.get_string("Publisher").ok(),
                    install_location: sub.get_string("InstallLocation").ok(),
                    uninstall_string: sub.get_string("UninstallString").ok(),
                    key_path: format!("{key_path}\\{sk}"),
                });
            }
        }
    }

    pkgs
}

fn merge_directories(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    fn is_ancestor(ancestor: &Path, path: &Path) -> bool {
        path.starts_with(ancestor) && path != ancestor
    }

    if paths.is_empty() {
        return vec![];
    }

    let mut normalized_paths: Vec<PathBuf> = paths
        .iter()
        .map(|p| p.normalize())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    normalized_paths.sort();

    let mut result = Vec::new();

    for path in normalized_paths {
        // Check if the current path is a subdirectory of any existing path
        let is_subdirectory = result.iter().any(|root: &PathBuf| is_ancestor(root, &path));

        if !is_subdirectory {
            result.push(path);
        }
    }

    result
}

fn collect_installed_dir(list: Vec<InstalledPackage>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    for pkg in list {
        // Prefer install_location
        if let Some(location) = &pkg.install_location {
            if location.trim().is_empty() {
                continue;
            }
            if let Ok(path) =
                std::path::absolute(PathBuf::from(location.trim_matches(['"', '\'', ' '])))
            {
                dirs.push(path);
            }
            continue;
        }

        // If install_location is empty, try to extract path from uninstall_string
        if let Some(uninstall_str) = &pkg.uninstall_string {
            if let Some(path) = extract_path_from_uninstall_string(uninstall_str) {
                dirs.push(path);
            }
        }
    }

    merge_directories(dirs)
}

/// Expand environment variables
fn expand_environment_variables(path: &str) -> String {
    unsafe {
        let input = HSTRING::from(path);
        let mut buffer = vec![0u16; 32767]; // MAX_PATH length
        let result = ExpandEnvironmentStringsW(&input, Some(&mut buffer));

        if result > 0 && result <= buffer.len() as u32 {
            // Remove trailing null characters
            let end = buffer.iter().position(|&x| x == 0).unwrap_or(buffer.len());
            String::from_utf16_lossy(&buffer[..end])
        } else {
            // If expansion fails, return the original string
            path.to_string()
        }
    }
}

/// Extract path from uninstall string
fn extract_path_from_uninstall_string(uninstall_str: &str) -> Option<PathBuf> {
    let trimmed = uninstall_str.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Handle quoted paths, e.g. "C:\Program Files\App\uninstall.exe"
    let mut path_str = None;
    if trimmed.starts_with(['"', '\'']) {
        // Find matching end quote
        let p = if let Some(end_quote_pos) = trimmed[1..].find(['"', '\'']) {
            &trimmed[1..end_quote_pos + 1]
        } else {
            // 没有结束引号，取引号后的所有内容
            &trimmed[1..]
        }
        .trim();
        if p.ends_with(".exe") {
            path_str = Some(p);
        }
    }

    if path_str.is_none() {
        // Search from the end to find the content before the first .exe
        if let Some(end_exe_pos) = trimmed.rfind(".exe") {
            path_str = Some(&trimmed[..end_exe_pos + 4]);
        } else {
            path_str = Some(trimmed);
        }
    }

    let path_str = path_str?;

    // Expand environment variables
    let expanded_path_str = expand_environment_variables(path_str);

    let path = PathBuf::from(expanded_path_str);

    if !path.has_root() {
        return None;
    }

    // If the path points to an executable, return its parent directory
    if path.extension().is_some() {
        path.parent().and_then(|p| std::path::absolute(p).ok())
    } else {
        Some(path)
    }
}

pub fn collect_installed_apps() -> windows::core::Result<Vec<InstalledPackage>> {
    // HKLM – 64‑bit view
    let key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    let hklm = LOCAL_MACHINE.open(key_path)?;

    let mut pkgs = harvest_uninstall_hive(&hklm, key_path);

    // HKLM – 32‑bit view on 64‑bit OS (optional)
    let key_path_wow = r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
    let hklm_wow = LOCAL_MACHINE.open(key_path_wow)?;
    pkgs.extend(harvest_uninstall_hive(&hklm_wow, key_path_wow));

    // HKCU – per‑user installs
    let key_path_cu = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    let hkcu = CURRENT_USER.open(key_path_cu)?;

    pkgs.extend(harvest_uninstall_hive(&hkcu, key_path_cu));

    // Simple de‑dup by (name, version).  Uses a HashSet to retain
    // only the first occurrence we encounter.
    let mut seen = HashMap::new();
    for pkg in pkgs.into_iter() {
        match seen.get_mut(&(pkg.name.clone(), pkg.version.clone())) {
            None => {
                seen.insert((pkg.name.clone(), pkg.version.clone()), pkg);
            }
            // Merge the install location if it's not set
            Some(existing) => {
                if existing.install_location.is_none() {
                    *existing = pkg;
                }
            }
        }
    }
    let pkgs = seen.into_values().collect::<Vec<_>>();

    Ok(pkgs)
}
