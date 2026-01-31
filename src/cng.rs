// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Aalivexy

use crate::bio::{authenticate_with_biometrics, get_biometrics_status};
use anyhow::{Result, bail};
use std::{ffi::c_void, ptr::null_mut};
use windows::Win32::{
    Foundation::{NTE_BAD_KEYSET, NTE_NO_MORE_ITEMS},
    Security::Cryptography::{
        BCRYPT_RSA_ALGORITHM, CERT_KEY_SPEC, MS_PLATFORM_KEY_STORAGE_PROVIDER,
        NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY,
        NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_PAD_PKCS1_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
        NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt, NCryptEnumKeys,
        NCryptFinalizeKey, NCryptFreeBuffer, NCryptKeyName, NCryptOpenKey,
        NCryptOpenStorageProvider, NCryptSetProperty,
    },
};
use windows::core::PCWSTR;
use windows_strings::HSTRING;

pub fn default_key_name() -> HSTRING {
    HSTRING::from("bw-bio")
}

pub struct CngProvider {
    provider: NCRYPT_PROV_HANDLE,
}

impl CngProvider {
    pub fn new() -> Result<Self> {
        let mut provider = NCRYPT_PROV_HANDLE::default();
        unsafe {
            NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0)?;
        }
        Ok(Self { provider })
    }

    pub fn enum_keys(&self) -> Result<Vec<NCryptKeyName>> {
        unsafe {
            let mut enum_state: *mut c_void = null_mut();
            let mut keys = Vec::new();
            loop {
                let mut key_ptr: *mut NCryptKeyName = null_mut();
                match NCryptEnumKeys(
                    self.provider,
                    PCWSTR::null(),
                    &mut key_ptr,
                    &mut enum_state,
                    NCRYPT_SILENT_FLAG,
                ) {
                    Ok(_) => {
                        if key_ptr.is_null() {
                            continue;
                        }
                        let key = *key_ptr;
                        keys.push(key);
                        NCryptFreeBuffer(key_ptr as *mut _)?;
                    }
                    Err(e) if e.code() == NTE_NO_MORE_ITEMS => break,
                    Err(e) => return Err(e.into()),
                }
            }
            NCryptFreeBuffer(enum_state)?;
            Ok(keys)
        }
    }

    pub fn create_key(&self, key_name: HSTRING) -> Result<CngKey> {
        unsafe {
            let mut key_handle = NCRYPT_KEY_HANDLE::default();
            NCryptCreatePersistedKey(
                self.provider,
                &mut key_handle,
                BCRYPT_RSA_ALGORITHM,
                PCWSTR::from_raw(key_name.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_OVERWRITE_KEY_FLAG,
            )?;
            let key_length = 2048u32;
            NCryptSetProperty(
                key_handle.into(),
                NCRYPT_LENGTH_PROPERTY,
                &key_length.to_ne_bytes(),
                NCRYPT_SILENT_FLAG,
            )?;
            let export_policy = 0u32;
            NCryptSetProperty(
                key_handle.into(),
                NCRYPT_EXPORT_POLICY_PROPERTY,
                &export_policy.to_ne_bytes(),
                NCRYPT_SILENT_FLAG,
            )?;
            NCryptFinalizeKey(key_handle, NCRYPT_FLAGS(0))?;
            Ok(CngKey::new(key_handle))
        }
    }

    pub fn open_key(&self, key_name: HSTRING) -> Result<CngKey> {
        unsafe {
            let mut key_handle = NCRYPT_KEY_HANDLE::default();
            match NCryptOpenKey(
                self.provider,
                &mut key_handle,
                PCWSTR::from_raw(key_name.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            ) {
                Ok(_) => Ok(CngKey::new(key_handle)),
                Err(e) if e.code() == NTE_BAD_KEYSET => self.create_key(key_name),
                Err(e) => Err(e.into()),
            }
        }
    }
}

pub struct CngKey {
    handle: NCRYPT_KEY_HANDLE,
}

impl CngKey {
    pub fn new(handle: NCRYPT_KEY_HANDLE) -> Self {
        Self { handle }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let mut out_len = 0u32;
            NCryptEncrypt(
                self.handle,
                Some(data),
                None,
                None,
                &mut out_len,
                NCRYPT_PAD_PKCS1_FLAG,
            )?;
            let mut buffer = vec![0u8; out_len as usize];
            NCryptEncrypt(
                self.handle,
                Some(data),
                None,
                Some(&mut buffer),
                &mut out_len,
                NCRYPT_PAD_PKCS1_FLAG,
            )?;
            buffer.resize(out_len as usize, 0);
            Ok(buffer)
        }
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Ask the user to confirm decryption via biometrics
        if get_biometrics_status() != 0 {
            bail!("Biometric authentication not available");
        } else if !authenticate_with_biometrics() {
            bail!("Biometric authentication failed");
        }
        unsafe {
            let mut out_len = 0u32;
            NCryptDecrypt(
                self.handle,
                Some(data),
                None,
                None,
                &mut out_len,
                NCRYPT_PAD_PKCS1_FLAG,
            )?;
            let mut buffer = vec![0u8; out_len as usize];
            NCryptDecrypt(
                self.handle,
                Some(data),
                None,
                Some(&mut buffer),
                &mut out_len,
                NCRYPT_PAD_PKCS1_FLAG,
            )?;
            buffer.resize(out_len as usize, 0);
            Ok(buffer)
        }
    }

    pub fn delete(self) -> Result<()> {
        unsafe {
            NCryptDeleteKey(self.handle, 0)?;
        }
        Ok(())
    }
}
