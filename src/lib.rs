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

/// Builder for configuring which sources to collect installed packages from.
///
/// ```no_run
/// use list_installed_apps::InstalledApps;
/// // Default: GUI apps only
/// let pkgs = InstalledApps::default().collect().unwrap();
///
/// // All sources (macOS: .app + pkgutil + homebrew)
/// let pkgs = InstalledApps::all().collect().unwrap();
/// ```
pub struct InstalledApps {
    pub(crate) gui: bool,
    pub(crate) appx: bool,
    pub(crate) pkgutil: bool,
    pub(crate) brew: bool,
}

impl Default for InstalledApps {
    fn default() -> Self {
        Self {
            gui: true,
            appx: false,
            pkgutil: false,
            brew: false,
        }
    }
}

impl InstalledApps {
    /// Enable all available sources.
    pub fn all() -> Self {
        Self {
            gui: true,
            appx: true,
            pkgutil: true,
            brew: true,
        }
    }

    /// Collect GUI applications (.app bundles on macOS, registry on Windows).
    pub fn gui(mut self, enable: bool) -> Self {
        self.gui = enable;
        self
    }

    /// Collect AppX/MSIX packages (Windows only, no-op on other platforms).
    pub fn appx(mut self, enable: bool) -> Self {
        self.appx = enable;
        self
    }

    /// Collect packages from `pkgutil` receipts (macOS only, no-op on other platforms).
    pub fn pkgutil(mut self, enable: bool) -> Self {
        self.pkgutil = enable;
        self
    }

    /// Collect packages from Homebrew (macOS only, no-op on other platforms).
    pub fn brew(mut self, enable: bool) -> Self {
        self.brew = enable;
        self
    }

    /// Execute the collection with the configured sources.
    pub fn collect(self) -> std::io::Result<Vec<InstalledPackage>> {
        platform_collect(self)
    }
}

/// Convenience function — equivalent to `InstalledApps::default().collect()`.
pub fn collect_installed_apps() -> std::io::Result<Vec<InstalledPackage>> {
    InstalledApps::default().collect()
}

#[cfg(windows)]
fn platform_collect(config: InstalledApps) -> std::io::Result<Vec<InstalledPackage>> {
    windows_impl::collect(config)
}

#[cfg(target_os = "macos")]
fn platform_collect(config: InstalledApps) -> std::io::Result<Vec<InstalledPackage>> {
    macos::collect(config)
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_collect(_config: InstalledApps) -> std::io::Result<Vec<InstalledPackage>> {
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
