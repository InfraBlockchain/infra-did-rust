use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap as Map;

use super::uri::URI;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Schema {
    pub id: URI,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}
