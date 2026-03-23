pub use crate::{collect_installed_apps, InstalledPackage, InstalledPkgsExt};

#[cfg(windows)]
pub use windows::core::Error as WinError;
