//! Strict response contracts shared by the two v2board-new node sections.
use super::types::{speed_limit_bps, User};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind, Result};

fn invalid(message: &str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

pub(super) fn users(value: &Value) -> Result<Vec<User>> {
    let entries = value
        .get("users")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("UniProxy user response has no users array"))?;
    let mut ids = HashSet::new();
    let mut credentials = HashSet::new();
    entries
        .iter()
        .map(|entry| {
            let id = entry
                .get("id")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
                .filter(|n| *n > 0)
                .ok_or_else(|| invalid("UniProxy user has invalid id"))?;
            let uuid = entry
                .get("uuid")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| invalid("UniProxy user has missing credentials"))?;
            if !ids.insert(id) || !credentials.insert(uuid) {
                return Err(invalid(
                    "UniProxy user list contains duplicate ids or credentials",
                ));
            }
            let device_limit = match entry.get("device_limit").filter(|v| !v.is_null()) {
                None => 0,
                Some(value) => value
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| invalid("UniProxy user has invalid device_limit"))?,
            };
            Ok(User {
                id,
                uuid: uuid.into(),
                speed_limit: speed_limit_bps(entry.get("speed_limit"))?,
                device_limit,
                password: entry
                    .get("password")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                method: entry
                    .get("method")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                port: entry
                    .get("port")
                    .and_then(Value::as_u64)
                    .and_then(|n| u16::try_from(n).ok()),
                flow: entry.get("flow").and_then(Value::as_str).map(str::to_owned),
            })
        })
        .collect()
}

pub(super) fn alive(value: &Value) -> Result<HashMap<u32, u32>> {
    let entries = value
        .get("alive")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("UniProxy alive response has no alive object"))?;
    entries
        .iter()
        .map(|(key, value)| {
            let id = key
                .parse::<u32>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| invalid("UniProxy alive response has invalid user id"))?;
            let count = value
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| invalid("UniProxy alive response has invalid count"))?;
            Ok((id, count))
        })
        .collect()
}

pub(super) async fn acknowledge(
    response: reqwest::Response,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let value: Value = response.error_for_status()?.json().await?;
    if value.get("data").and_then(Value::as_bool) != Some(true) {
        return Err(invalid("UniProxy report was not acknowledged with data=true").into());
    }
    Ok(())
}
