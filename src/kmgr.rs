// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Aalivexy

use crate::cng::default_key_name;
use crate::cng::{CngKey, CngProvider};
use anyhow::Result;
use std::{
    env::current_exe,
    fs::{create_dir_all, read, read_dir, remove_file, write},
    path::PathBuf,
};
use windows_strings::HSTRING;

pub struct KeyManager {
    cng_provider: CngProvider,
    cng_key: CngKey,
    bw_key_directory: PathBuf,
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new(
            default_key_name(),
            current_exe()
                .expect("Failed to get current executable path")
                .parent()
                .expect("Failed to get parent directory")
                .to_path_buf()
                .join("keys"),
        )
    }
}

impl KeyManager {
    pub fn new(cng_key_name: HSTRING, bw_key_directory: PathBuf) -> Self {
        let cng_provider = CngProvider::new().expect("Failed to create CNG provider");
        let cng_key = cng_provider
            .open_key(cng_key_name)
            .expect("Failed to open CNG key");
        Self {
            cng_provider,
            cng_key,
            bw_key_directory,
        }
    }

    pub fn cng_provider(&self) -> &CngProvider {
        &self.cng_provider
    }

    pub fn cng_key(&self) -> &CngKey {
        &self.cng_key
    }

    pub fn list_keys(&self) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        if self.bw_key_directory.exists() {
            for entry in read_dir(&self.bw_key_directory)? {
                let entry = entry?;
                if entry.file_type()?.is_file()
                    && let Some(name) = entry.file_name().to_str()
                {
                    keys.push(name.to_string());
                }
            }
        }
        Ok(keys)
    }

    pub fn import_key(&self, user_id: &str, bw_key: &str) -> Result<()> {
        create_dir_all(&self.bw_key_directory)?;
        let encrypted = self.cng_key.encrypt(bw_key.as_bytes())?;
        let file_path = self.bw_key_directory.join(user_id);
        write(file_path, encrypted)?;
        Ok(())
    }

    pub fn check_key_exists(&self, user_id: &str) -> Result<bool> {
        let file_path = self.bw_key_directory.join(user_id);
        Ok(file_path.exists())
    }

    pub fn export_key(&self, user_id: &str) -> Result<String> {
        let file_path = self.bw_key_directory.join(user_id);
        let encrypted = read(file_path)?;
        let decrypted = self.cng_key.decrypt(&encrypted)?;
        let bw_key = String::from_utf8(decrypted)?;
        Ok(bw_key)
    }

    pub fn delete_key(&self, user_id: &str) -> Result<()> {
        let file_path = self.bw_key_directory.join(user_id);
        if file_path.exists() {
            remove_file(file_path)?;
        }
        Ok(())
    }
}
