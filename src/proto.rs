// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 Aalivexy

use crate::crypto::{base64_decode, base64_encode};
use anyhow::Result;
use serde::{Deserialize, Serialize, Serializer};
use std::{fmt::Display, time::SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncString {
    #[serde(rename = "encryptionType")]
    enc_type: i32,
    data: String,
    iv: String,
    mac: String,
}

impl EncString {
    pub fn new(data: &[u8], iv: &[u8; 16], mac: &[u8; 32]) -> Self {
        Self {
            enc_type: 2,
            data: base64_encode(data),
            iv: base64_encode(iv),
            mac: base64_encode(mac),
        }
    }

    pub fn data(&self) -> Result<Vec<u8>> {
        base64_decode(&self.data)
    }

    pub fn iv(&self) -> Result<Vec<u8>> {
        base64_decode(&self.iv)
    }

    pub fn mac(&self) -> Result<Vec<u8>> {
        base64_decode(&self.mac)
    }
}

impl Display for EncString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}|{}|{}",
            self.enc_type, self.iv, self.data, self.mac
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct EncryptedMessage {
    command: String,
    #[serde(rename = "messageId")]
    message_id: i64,
    #[serde(rename = "userId")]
    user_id: Option<String>,
}

impl EncryptedMessage {
    pub fn command(&self) -> &str {
        &self.command
    }

    pub fn message_id(&self) -> i64 {
        self.message_id
    }

    pub fn user_id(&self) -> Option<&str> {
        self.user_id.as_deref()
    }
}

#[derive(Debug, Clone)]
pub enum ResponseData {
    Number(i32),
    Bool(bool),
}

impl Serialize for ResponseData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ResponseData::Number(n) => serializer.serialize_i32(*n),
            ResponseData::Bool(b) => serializer.serialize_bool(*b),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseMessage {
    timestamp: u64,
    command: String,
    #[serde(rename = "messageId")]
    message_id: i64,
    response: ResponseData,
    #[serde(rename = "userKeyB64")]
    key: Option<String>,
}

impl ResponseMessage {
    pub fn new<T: Into<ResponseData>>(command: &str, message_id: i64, response: T) -> Self {
        Self::with_key(command, message_id, response, None)
    }

    pub fn with_key<T: Into<ResponseData>>(
        command: &str,
        message_id: i64,
        response: T,
        key: Option<String>,
    ) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            command: command.to_string(),
            message_id,
            response: response.into(),
            key,
        }
    }

    pub fn message_id(&self) -> i64 {
        self.message_id
    }
}
