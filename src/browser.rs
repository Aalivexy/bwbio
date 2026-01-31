// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Aalivexy

use crate::{
    bio::{authenticate_with_biometrics, get_biometrics_status},
    crypto::{Aes256CbcHmacKey, rsa_encrypt},
    kmgr::KeyManager,
    proto::{EncString, EncryptedMessage, ResponseData, ResponseMessage},
};
use anyhow::{Result, anyhow};
use serde_json::{Value, from_slice, from_value, json, to_vec};
use std::{
    io::{BufReader, ErrorKind, Read, Write, stdin, stdout},
    sync::OnceLock,
};

static SHARED_SECRET: OnceLock<Aes256CbcHmacKey> = OnceLock::new();
static KEY_MANAGER: OnceLock<KeyManager> = OnceLock::new();

pub fn launch_native_messaging() -> Result<()> {
    SHARED_SECRET.get_or_init(Aes256CbcHmacKey::new);
    KEY_MANAGER.get_or_init(KeyManager::default);
    let mut r = BufReader::new(stdin());
    send(json!({
        "command": "connected",
        "app_id": "com.8bit.bitwarden"
    }))?;

    loop {
        let len_buf = read_exact(&mut r, 4)?;
        if len_buf.is_empty() {
            break Ok(());
        }
        let len = u32::from_ne_bytes(len_buf.try_into().unwrap());

        let msg_buf = read_exact(&mut r, len as usize)?;
        if msg_buf.is_empty() {
            break Ok(());
        }

        parse_message(&msg_buf)?
    }
}

fn send(msg: Value) -> Result<()> {
    let serialized = to_vec(&msg)?;
    stdout().write_all(&(serialized.len() as u32).to_ne_bytes())?;
    stdout().write_all(&serialized)?;
    stdout().flush()?;
    Ok(())
}

fn send_encrypted(app_id: &str, message: ResponseMessage) -> Result<()> {
    let enc_str = SHARED_SECRET.wait().encrypt(&to_vec(&message)?)?;
    send(json!({
        "appId": app_id,
        "messageId": message.message_id(),
        "message": {
            "encryptedString": enc_str.to_string()
        }
    }))
}

fn read_exact<R: Read>(reader: &mut R, buf_len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; buf_len];
    match reader.read_exact(&mut buf) {
        Ok(()) => Ok(buf),
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
            Ok(buf) // EOF
        }
        Err(e) => Err(e.into()),
    }
}

fn parse_message(msg: &[u8]) -> Result<()> {
    let msg = from_slice::<Value>(msg)?;
    let app_id = msg
        .get("appId")
        .and_then(Value::as_str)
        .ok_or(anyhow!("Missing 'appId' field"))?;
    if let Some(message) = msg.get("message")
        && let Some(command) = message.get("command")
        && let Some(command) = command.as_str()
        && command == "setupEncryption"
        && let Some(public_key) = message.get("publicKey")
        && let Some(public_key) = public_key.as_str()
    {
        let shared_secret = rsa_encrypt(public_key, &SHARED_SECRET.wait().to_vec())?;
        send(json!({
            "command": "setupEncryption",
            "appId": app_id,
            "sharedSecret": shared_secret
        }))
    } else {
        let enc_str: EncString = from_value(
            msg.get("message")
                .ok_or(anyhow!("Missing 'message' field"))?
                .clone(),
        )?;
        handle_message(
            app_id,
            from_slice(&SHARED_SECRET.wait().decrypt(
                &enc_str.iv()?.as_slice().try_into()?,
                &enc_str.mac()?.as_slice().try_into()?,
                &enc_str.data()?,
            )?)?,
        )
    }
}

fn handle_message(app_id: &str, msg: EncryptedMessage) -> Result<()> {
    match msg.command() {
        "unlockWithBiometricsForUser" => {
            let user_id = msg.user_id().ok_or(anyhow!("Missing 'userId' field"))?;
            KEY_MANAGER
                .wait()
                .export_key(user_id)
                .and_then(|bw_key| {
                    send_encrypted(
                        app_id,
                        ResponseMessage::with_key(
                            "unlockWithBiometricsForUser",
                            msg.message_id(),
                            ResponseData::Bool(true),
                            Some(bw_key),
                        ),
                    )
                })
                .or_else(|_| {
                    send_encrypted(
                        app_id,
                        ResponseMessage::new(
                            "unlockWithBiometricsForUser",
                            msg.message_id(),
                            ResponseData::Bool(false),
                        ),
                    )
                })?;
        }
        "authenticateWithBiometrics" => {
            send_encrypted(
                app_id,
                ResponseMessage::new(
                    "authenticateWithBiometrics",
                    msg.message_id(),
                    ResponseData::Bool(authenticate_with_biometrics()),
                ),
            )?;
        }
        "getBiometricsStatus" => {
            send_encrypted(
                app_id,
                ResponseMessage::new(
                    "getBiometricsStatus",
                    msg.message_id(),
                    ResponseData::Number(get_biometrics_status()),
                ),
            )?;
        }
        "getBiometricsStatusForUser" => {
            let user_id = msg.user_id().ok_or(anyhow!("Missing 'userId' field"))?;
            KEY_MANAGER
                .wait()
                .check_key_exists(user_id)
                .and_then(|exists| {
                    send_encrypted(
                        app_id,
                        ResponseMessage::new(
                            "getBiometricsStatusForUser",
                            msg.message_id(),
                            ResponseData::Number(if exists { 0 } else { 4 }),
                        ),
                    )
                })?;
        }
        _ => {}
    }

    Ok(())
}
