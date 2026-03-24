# list-installed-apps

A cross-platform Rust library for listing installed applications.

## Supported platforms

| Platform | Sources |
|----------|---------|
| **Windows** | Registry (`Uninstall` keys), AppX/MSIX packages (UWP & Microsoft Store) |
| **macOS** | `.app` bundles, `pkgutil` receipts, Homebrew |

## Usage

```toml
[dependencies]
list-installed-apps = "0.3"
```

### Quick start

```rust
use list_installed_apps::InstalledApps;

// Default: GUI apps from registry (Windows) or .app bundles (macOS)
let pkgs = InstalledApps::default().collect().unwrap();

// All available sources
let pkgs = InstalledApps::all().collect().unwrap();
```

### Selecting sources

```rust
use list_installed_apps::InstalledApps;

// Windows: only AppX/MSIX packages (Calculator, Photos, Terminal, etc.)
let pkgs = InstalledApps::default()
    .gui(false)
    .appx(true)
    .collect()
    .unwrap();

// macOS: .app bundles + Homebrew, skip pkgutil
let pkgs = InstalledApps::default()
    .brew(true)
    .collect()
    .unwrap();
```

### Extracting install directories

```rust
use list_installed_apps::prelude::*;

let dirs = InstalledApps::all()
    .collect()
    .unwrap()
    .collect_installed_dir();
```

## `InstalledPackage` fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | `String` | Display name |
| `version` | `Option<String>` | Version string |
| `publisher` | `Option<String>` | Publisher / developer |
| `install_location` | `Option<String>` | Install directory path |
| `uninstall_string` | `Option<String>` | Uninstall command (registry apps only) |
| `identifier` | `String` | Registry key path (Windows), AppX family name, or bundle identifier (macOS) |

## License

MIT
