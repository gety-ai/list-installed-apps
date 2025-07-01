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
// You'll get an array of JSON objects, each with the following
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
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};
use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows::core::HSTRING;
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

fn collect_installed_dir(list: Vec<InstalledPackage>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    for pkg in list {
        // 优先使用 install_location
        if let Some(location) = &pkg.install_location
            && !location.trim().is_empty()
        {
            if let Ok(path) =
                std::path::absolute(PathBuf::from(location.trim_matches(['"', '\'', ' '])))
            {
                dirs.push(path);
            }
            continue;
        }

        // 如果 install_location 为空，尝试从 uninstall_string 中提取路径
        if let Some(uninstall_str) = &pkg.uninstall_string
            && let Some(path) = extract_path_from_uninstall_string(uninstall_str)
        {
            dirs.push(path);
        }
    }

    // 去重并返回
    let mut unique_dirs: Vec<PathBuf> = dirs
        .into_iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect::<HashSet<_>>()
        .into_iter()
        .map(|p| PathBuf::from(p.as_str()))
        .collect();
    unique_dirs.sort();
    unique_dirs
}

/// 展开环境变量
fn expand_environment_variables(path: &str) -> String {
    unsafe {
        let input = HSTRING::from(path);
        let mut buffer = vec![0u16; 32767]; // MAX_PATH 长度
        let result = ExpandEnvironmentStringsW(&input, Some(&mut buffer));

        if result > 0 && result <= buffer.len() as u32 {
            // 移除末尾的空字符
            let end = buffer.iter().position(|&x| x == 0).unwrap_or(buffer.len());
            String::from_utf16_lossy(&buffer[..end])
        } else {
            // 如果展开失败，返回原始字符串
            path.to_string()
        }
    }
}

/// 从卸载字符串中提取路径
fn extract_path_from_uninstall_string(uninstall_str: &str) -> Option<PathBuf> {
    let trimmed = uninstall_str.trim();
    if trimmed.is_empty() {
        return None;
    }

    // 处理引号包围的路径，如 "C:\Program Files\App\uninstall.exe"
    let mut path_str = None;
    if trimmed.starts_with(['"', '\'']) {
        // 找到匹配的结束引号
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
        // 从后往前搜索，找到第一个 .exe 之前的所有内容
        if let Some(end_exe_pos) = trimmed.rfind(".exe") {
            path_str = Some(&trimmed[..end_exe_pos + 4]);
        } else {
            path_str = Some(trimmed);
        }
    }

    let path_str = path_str?;

    // expand environment variables
    let expanded_path_str = expand_environment_variables(path_str);

    let path = PathBuf::from(expanded_path_str);

    if !path.has_root() {
        return None;
    }

    // 如果路径指向一个可执行文件，返回其父目录
    if path.extension().is_some() {
        path.parent().and_then(|p| std::path::absolute(p).ok())
    } else {
        Some(path)
    }
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
    pkgs = seen.into_values().collect();
    let dirs = collect_installed_dir(pkgs);

    // Emit pretty‑printed JSON – pipe / redirect as needed
    println!("{}", serde_json::to_string_pretty(&dirs)?);
    Ok(())
}
