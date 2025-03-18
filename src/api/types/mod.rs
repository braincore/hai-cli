// DO NOT EDIT
// This file was @generated by Stone

#![allow(
    dead_code,
    clippy::too_many_arguments,
    clippy::too_many_arguments,
    clippy::large_enum_variant,
    clippy::result_large_err,
    clippy::doc_markdown
)]

#[allow(unused_imports)]
use base64::{engine::general_purpose::STANDARD_NO_PAD as BASE64, Engine as _};

pub mod account;
pub mod asset;
pub mod common;
pub mod task;
pub(crate) fn eat_json_fields<'de, V>(map: &mut V) -> Result<(), V::Error>
where
    V: ::serde::de::MapAccess<'de>,
{
    while map.next_entry::<&str, ::serde_json::Value>()?.is_some() { /* ignore */ }
    Ok(())
}
