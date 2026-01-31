// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Aalivexy

use crate::proto::EncString;
use aes::{
    Aes256,
    cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7},
};
use anyhow::{Result, anyhow};
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use rand::{Rng, RngExt};
use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePublicKey};
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(input)?)
}

pub fn base64_encode(input: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(input)
}

pub fn rsa_encrypt(public_key_b64: &str, message: &[u8]) -> Result<String> {
    let public_key = base64_decode(public_key_b64)?;
    let public_key = RsaPublicKey::from_public_key_der(&public_key)?;
    let mut rng = rand::rng();
    let padding = Oaep::<Sha1>::new();
    let ct = public_key.encrypt(&mut rng, padding, message)?;
    Ok(base64_encode(&ct))
}

pub fn generate_mac(mac_key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<[u8; 32]> {
    let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key).unwrap();
    hmac.update(iv);
    hmac.update(data);
    Ok((*hmac.finalize().into_bytes()).try_into().unwrap())
}

pub struct Aes256CbcHmacKey {
    enc_key: [u8; 32],
    mac_key: [u8; 32],
}

impl Aes256CbcHmacKey {
    pub fn new() -> Self {
        let mut rng = rand::rng();
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        rng.fill_bytes(&mut enc_key);
        rng.fill_bytes(&mut mac_key);
        Self { enc_key, mac_key }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut key_vec = Vec::with_capacity(64);
        key_vec.extend_from_slice(&self.enc_key);
        key_vec.extend_from_slice(&self.mac_key);
        key_vec
    }

    pub fn decrypt(&self, iv: &[u8; 16], mac: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
        let res = generate_mac(&self.mac_key, iv, data)?;
        if res.ct_ne(mac).into() {
            return Err(anyhow!("MAC verification failed"));
        }
        cbc::Decryptor::<Aes256>::new(&self.enc_key.into(), iv.into())
            .decrypt_padded_vec::<Pkcs7>(data)
            .map_err(|e| anyhow!("AES decrypt error: {:?}", e))
    }

    pub fn encrypt(&self, msg: &[u8]) -> Result<EncString> {
        let iv = rand::rng().random::<[u8; 16]>();
        let data = cbc::Encryptor::<Aes256>::new(&self.enc_key.into(), &iv.into())
            .encrypt_padded_vec::<Pkcs7>(msg);
        let mac = generate_mac(&self.mac_key, &iv, &data)?;

        Ok(EncString::new(&data, &iv, &mac))
    }
}

impl Default for Aes256CbcHmacKey {
    fn default() -> Self {
        Self::new()
    }
}
