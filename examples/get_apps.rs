use list_installed_apps::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pkgs = collect_installed_apps()?;
    println!("pkgs: {pkgs:?}",);
    let dirs = pkgs.collect_installed_dir();
    println!("{}", serde_json::to_string_pretty(&dirs)?);
    Ok(())
}
