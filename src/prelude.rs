pub use crate::{collect_installed_apps, InstalledApps, InstalledPackage, InstalledPkgsExt};

#[cfg(windows)]
pub use windows::core::Error as WinError;
