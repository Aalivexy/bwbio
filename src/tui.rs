// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Aalivexy

use crate::cng::default_key_name;
use crate::kmgr::KeyManager;
use dialoguer::{Confirm, Input, Select};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use windows_registry::CURRENT_USER;
use windows_strings::HSTRING;

const MANIFEST_NAME: &str = "chrome.json";
const REG_KEYS: [&str; 2] = [
    "software\\google\\chrome\\nativemessaginghosts\\com.8bit.bitwarden",
    "software\\microsoft\\edge\\nativemessaginghosts\\com.8bit.bitwarden",
];

fn pause_before_exit() {
    let _: Result<String, _> = Input::new()
        .with_prompt("Press Enter to exit")
        .allow_empty(true)
        .interact_text();
}

fn spawn_and_exit(path: &Path) -> Result<(), String> {
    match Command::new(path).spawn() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to spawn '{}': {e}", path.display())),
    }
}

fn register_native_messaging_manifest(manifest_path: &Path) -> Result<(), String> {
    let manifest_abs = std::fs::canonicalize(manifest_path)
        .map_err(|e| format!("Failed to canonicalize manifest path: {e}"))?;
    let manifest_str = manifest_abs.to_string_lossy().to_string();
    let manifest_str = manifest_str.strip_prefix(r"\\?\").unwrap_or(&manifest_str);
    let mut success_count = 0;

    for key_path in REG_KEYS {
        match CURRENT_USER.create(key_path) {
            Ok(key) => match key.set_string("", manifest_str) {
                Ok(_) => success_count += 1,
                Err(e) => eprintln!("Warning: failed to set default value for {key_path}: {e}"),
            },
            Err(e) => eprintln!("Warning: failed to create/open registry key {key_path}: {e}"),
        }
    }

    if success_count == 0 {
        eprintln!(
            "Warning: no supported browsers detected or registry writes failed. Manually register {} if needed.",
            manifest_abs.display()
        );
    }

    Ok(())
}

fn unregister_native_messaging_manifest() {
    let mut any_success = false;
    for key_path in REG_KEYS {
        if CURRENT_USER.remove_tree(key_path).is_ok() {
            any_success = true;
        }
    }

    if !any_success {
        eprintln!(
            "Warning: no registry values removed (no supported browsers detected or already unregistered)"
        );
    }
}

fn perform_install(install_dir: &Path) -> Result<(), String> {
    if let Err(e) = std::fs::create_dir_all(install_dir) {
        return Err(format!("Failed to create install directory: {e}"));
    }

    let current_exe =
        env::current_exe().map_err(|e| format!("Failed to get current exe path: {e}"))?;
    let target_exe = install_dir.join("bwbio.exe");
    if let Err(e) = std::fs::copy(&current_exe, &target_exe) {
        return Err(format!("Failed to copy exe to target location: {e}"));
    }
    let target_exe = std::fs::canonicalize(&target_exe)
        .unwrap_or(target_exe)
        .to_string_lossy()
        .to_string();
    let target_exe = target_exe.strip_prefix(r"\\?\").unwrap_or(&target_exe);

    let manifest = serde_json::json!({
        "name": "com.8bit.bitwarden",
        "description": "Bitwarden desktop <-> browser bridge",
        "path": target_exe,
        "type": "stdio",
        "allowed_origins": [
            "chrome-extension://nngceckbapebfimnlniiiahkandclblb/",
            "chrome-extension://hccnnhgbibccigepcmlgppchkpfdophk/",
            "chrome-extension://jbkfoedolllekgbhcbcoahefnbanhhlh/",
            "chrome-extension://ccnckbpmaceehanjmeomladnmlffdjgn/"
        ]
    });

    let manifest_path = install_dir.join("chrome.json");
    if let Err(e) = std::fs::write(&manifest_path, manifest.to_string()) {
        return Err(format!("Failed to write manifest: {e}"));
    }

    if let Err(e) = register_native_messaging_manifest(manifest_path.as_path()) {
        return Err(format!("Failed to write registry entries: {e}"));
    }

    Ok(())
}

fn perform_uninstall(install_dir: &Path, key_dir: &Path) -> Result<(), String> {
    unregister_native_messaging_manifest();

    if key_dir.exists()
        && let Err(e) = std::fs::remove_dir_all(key_dir)
    {
        eprintln!("Warning: failed to remove keys directory: {e}");
    }

    let manifest_path = install_dir.join(MANIFEST_NAME);
    if manifest_path.exists()
        && let Err(e) = std::fs::remove_file(&manifest_path)
    {
        eprintln!("Warning: failed to remove manifest: {e}");
    }

    if let Ok(cur) = env::current_exe() {
        let tmp = env::temp_dir().join("bwbio_uninstall.exe");
        if let Err(e) = std::fs::rename(&cur, &tmp) {
            eprintln!("Warning: failed to move exe to temp: {e}");
        } else if let Err(e) = std::fs::remove_dir_all(install_dir) {
            eprintln!("Warning: failed to remove install directory: {e}");
        }
    }

    if let Ok(provider) = crate::cng::CngProvider::new() {
        let key_name = match env::var("CNG_KEY_NAME") {
            Ok(s) => HSTRING::from(s),
            Err(_) => default_key_name(),
        };
        if let Ok(key) = provider.open_key(key_name)
            && let Err(e) = key.delete()
        {
            eprintln!("Warning: failed to delete CNG key: {e}");
        }
    }

    Ok(())
}

fn install_and_spawn(install_dir: &Path) -> Result<(), String> {
    perform_install(install_dir)?;
    let installed_exe = install_dir.join("bwbio.exe");
    spawn_and_exit(installed_exe.as_path())?;
    Ok(())
}

fn import_key_flow(kmgr: &KeyManager) -> Result<(), String> {
    let user_id = match Input::<String>::new()
        .with_prompt("User ID")
        .interact_text()
    {
        Ok(s) if s.trim().is_empty() => return Ok(()),
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

    let user_key = match Input::<String>::new()
        .with_prompt("User Key (base64)")
        .interact_text()
    {
        Ok(s) if s.trim().is_empty() => return Ok(()),
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

    match kmgr.import_key(&user_id, &user_key) {
        Ok(_) => println!("Key imported successfully."),
        Err(e) => eprintln!("Failed to import key: {e}"),
    }

    Ok(())
}

fn list_keys_menu(kmgr: &KeyManager) -> Result<(), String> {
    match kmgr.list_keys() {
        Ok(listed) => {
            if listed.is_empty() {
                println!("No keys found.");
                return Ok(());
            }
            let mut items = listed.clone();
            items.push("<Back>".to_string());
            let sel = Select::new().items(&items).default(0).interact();
            if let Ok(idx) = sel
                && idx < listed.len()
            {
                let selected = &listed[idx];
                let actions = vec!["Export", "Delete", "Back"];
                if let Ok(a) = Select::new().items(&actions).default(0).interact() {
                    match a {
                        0 => match kmgr.export_key(selected) {
                            Ok(k) => println!("{k}"),
                            Err(e) => eprintln!("Failed to export key: {e}"),
                        },
                        1 => match kmgr.delete_key(selected) {
                            Ok(_) => println!("Key deleted."),
                            Err(e) => eprintln!("Failed to delete key: {e}"),
                        },
                        _ => {}
                    }
                }
            }
        }
        Err(e) => eprintln!("Failed to list keys: {e}"),
    }

    Ok(())
}

fn init_menu(kmgr: &KeyManager, install_dir: &Path, key_dir: &Path) -> Result<(), String> {
    let items = vec!["Import key", "Uninstall", "Exit"];
    let selection = Select::new().items(&items).default(0).interact();
    if let Ok(choice) = selection {
        match choice {
            0 => {
                import_key_flow(kmgr)?;
            }
            1 => {
                if Confirm::new()
                    .with_prompt("Are you sure you want to uninstall? This will remove keys and integrations.")
                    .default(false)
                    .interact()
                    .unwrap_or(false)
                    && Confirm::new()
                        .with_prompt("This action is irreversible. Confirm uninstall again?")
                        .default(false)
                        .interact()
                        .unwrap_or(false)
                {
                    perform_uninstall(install_dir, key_dir)?;
                    println!("Uninstall finished.");
                    return Ok(());
                }
            }
            _ => return Ok(()),
        }
    }

    Ok(())
}

fn management_menu(kmgr: &KeyManager, install_dir: &Path, key_dir: &Path) -> Result<(), String> {
    loop {
        let items = vec![
            "Import key",
            "List keys",
            "Install browser integration",
            "Remove browser integration",
            "Uninstall",
            "Exit",
        ];
        let choice = Select::new().items(&items).default(0).interact();
        match choice {
            Ok(0) => {
                import_key_flow(kmgr)?;
            }
            Ok(1) => {
                list_keys_menu(kmgr)?;
            }
            Ok(2) => {
                let manifest_path = install_dir.join(MANIFEST_NAME);
                // register_native_messaging_manifest will canonicalize the path and return a
                // useful error if the file does not exist.
                match register_native_messaging_manifest(manifest_path.as_path()) {
                    Ok(_) => println!("Browser integration installed/updated."),
                    Err(e) => eprintln!("Failed to write registry manifest: {e}"),
                }
            }
            Ok(3) => {
                unregister_native_messaging_manifest();
                println!("Browser integration removed.");
            }
            Ok(4) => {
                if Confirm::new()
                    .with_prompt("Are you sure you want to uninstall? This will remove keys and integrations.")
                    .default(false)
                    .interact()
                    .unwrap_or(false)
                    && Confirm::new()
                        .with_prompt("This action is irreversible. Confirm uninstall again?")
                        .default(false)
                        .interact()
                        .unwrap_or(false)
                {
                    perform_uninstall(install_dir, key_dir)?;
                    println!("Uninstall finished.");
                    return Ok(());
                }
            }
            Ok(5) | Err(_) => return Ok(()),
            _ => {}
        }
    }
}

fn run_installed_flow(install_dir: &Path, current_exe: &Path) -> Result<(), String> {
    println!("Running from installed location: {}", current_exe.display());

    let key_name = match env::var("CNG_KEY_NAME") {
        Ok(s) => HSTRING::from(s),
        Err(_) => default_key_name(),
    };
    let key_dir = env::var("BW_KEY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            current_exe
                .parent()
                .expect("Failed to get parent dir")
                .to_path_buf()
                .join("keys")
        });

    let kmgr = KeyManager::new(key_name, key_dir.clone());

    match kmgr.list_keys() {
        Ok(keys) => {
            if keys.is_empty() {
                init_menu(&kmgr, install_dir, &key_dir)?;
            } else {
                management_menu(&kmgr, install_dir, &key_dir)?;
            }
        }
        Err(e) => return Err(format!("Failed to list keys: {e}")),
    }

    Ok(())
}

pub fn tui_cli() {
    let local_appdata = match env::var("LOCALAPPDATA") {
        Ok(s) => PathBuf::from(s),
        Err(_) => {
            eprintln!("LOCALAPPDATA not set. Cannot determine install path.");
            pause_before_exit();
            return;
        }
    };

    let install_dir = local_appdata.join("bwbio");
    let target_exe = install_dir.join("bwbio.exe");
    let current_exe = env::current_exe().ok();
    let current_exe_canon = current_exe
        .as_ref()
        .and_then(|p| std::fs::canonicalize(p).ok());
    let target_exe_canon = std::fs::canonicalize(&target_exe).ok();

    if target_exe.exists() {
        if let (Some(cur), Some(tgt)) = (current_exe_canon.as_ref(), target_exe_canon.as_ref()) {
            if cur == tgt {
                if let Err(e) = run_installed_flow(&install_dir, cur) {
                    eprintln!("{e}");
                    pause_before_exit();
                    return;
                }
            } else if let Err(e) = spawn_and_exit(target_exe.as_path()) {
                eprintln!("{e}");
                pause_before_exit();
                return;
            } else {
                return;
            }
        } else if let Err(e) = spawn_and_exit(target_exe.as_path()) {
            eprintln!("{e}");
            pause_before_exit();
            return;
        } else {
            return;
        }
    } else {
        let prompt = format!("Install bwbio to {}?", install_dir.display());
        match Confirm::new().with_prompt(prompt).default(false).interact() {
            Ok(true) => {
                println!("Installing to {install_dir:#?}...");
                if let Err(e) = install_and_spawn(&install_dir) {
                    eprintln!("Installation failed: {e}");
                    pause_before_exit();
                    return;
                } else {
                    return;
                }
            }
            Ok(false) => println!("Installation cancelled."),
            Err(e) => eprintln!("Failed to prompt for installation: {e}"),
        }
    }

    pause_before_exit();
}
