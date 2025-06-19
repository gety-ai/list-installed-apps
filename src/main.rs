// installed_packages.rs
// -------------------------------------------------------------
// Enumerate installed applications by reading the classic ARP
// (Add / Remove Programs) registry hives.  This roughly mirrors
// the "ARPInstalledSource" winget uses under the hood.
//
// ➤ Build & run
//   $ cargo new installed_packages && cd installed_packages
//   # paste this file into src/main.rs, then add the dependencies
//   $ cargo run --release > packages.json
//
// ➤ Cargo.toml snippet
// [dependencies]
// windows-registry = "0.7"
// serde            = { version = "1", features = ["derive"] }
// serde_json       = "1"
//
// You’ll get an array of JSON objects, each with the following
// shape (fields may be null if the registry value is absent):
// {
//   "name": "7-Zip 24.05 (x64)",
//   "version": "24.05",
//   "publisher": "Igor Pavlov",
//   "install_location": "C:/Program Files/7-Zip/",
//   "uninstall_string": "C:/Program Files/7-Zip/Uninstall.exe",
//   "key_path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\7-Zip"
// }
// -------------------------------------------------------------

use serde::Serialize;
use std::collections::HashSet;
use windows_registry::{CURRENT_USER, Key, LOCAL_MACHINE};

#[derive(Debug, Serialize)]
struct InstalledPackage {
    name: String,
    version: Option<String>,
    publisher: Option<String>,
    install_location: Option<String>,
    uninstall_string: Option<String>,
    key_path: String,
}

/// Helper – pull `DisplayName` entries from one `...\\Uninstall` hive
fn harvest_uninstall_hive(root: &Key, key_path: &str) -> Vec<InstalledPackage> {
    let mut pkgs = Vec::new();

    let keys = match root.keys() {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("Error opening keys: {}", e);
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
                    key_path: format!("{}\\{}", key_path, sk),
                });
            }
        }
    }

    pkgs
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    let mut seen = HashSet::new();
    pkgs.retain(|p| seen.insert((p.name.clone(), p.version.clone())));

    // Emit pretty‑printed JSON – pipe / redirect as needed
    println!("{}", serde_json::to_string_pretty(&pkgs)?);
    Ok(())
}
