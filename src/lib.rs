use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use normalize_path::NormalizePath;
use serde::Serialize;

pub mod prelude;

#[cfg(windows)]
mod windows_impl;
#[cfg(target_os = "macos")]
mod macos;

#[derive(Debug, Serialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_location: Option<String>,
    pub uninstall_string: Option<String>,
    pub key_path: String,
}

pub trait InstalledPkgsExt {
    fn collect_installed_dir(self) -> Vec<PathBuf>;
}

impl InstalledPkgsExt for Vec<InstalledPackage> {
    fn collect_installed_dir(self) -> Vec<PathBuf> {
        collect_installed_dir(self)
    }
}

#[cfg(windows)]
pub use windows_impl::collect_installed_apps;

#[cfg(target_os = "macos")]
pub use macos::collect_installed_apps;

#[cfg(not(any(windows, target_os = "macos")))]
pub fn collect_installed_apps() -> std::io::Result<Vec<InstalledPackage>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Platform not supported",
    ))
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

        // If install_location is empty, try to extract path from uninstall_string (Windows only)
        #[cfg(windows)]
        {
            if let Some(uninstall_str) = &pkg.uninstall_string {
                if let Some(path) =
                    windows_impl::extract_path_from_uninstall_string(uninstall_str)
                {
                    dirs.push(path);
                }
            }
        }
    }

    merge_directories(dirs)
}
