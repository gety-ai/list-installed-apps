use std::collections::BTreeSet;

use list_installed_apps::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pkgs = collect_installed_apps()?;
    println!("pkgs: {pkgs:?}",);
    let names = pkgs.iter().map(|p| &p.name).collect::<BTreeSet<_>>();
    println!("names: {}", serde_json::to_string_pretty(&names)?);
    let dirs = pkgs.collect_installed_dir();
    println!("{}", serde_json::to_string_pretty(&dirs)?);
    Ok(())
}
