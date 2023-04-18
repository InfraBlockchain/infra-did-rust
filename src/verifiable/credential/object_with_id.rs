use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap as Map;

use super::uri::URI;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ObjectWithId {
    pub id: URI,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}
