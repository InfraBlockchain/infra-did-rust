use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::uri::URI;
use std::collections::HashMap as Map;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<URI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

impl CredentialSubject {
    /// Check if the credential subject is empty
    ///
    /// An empty credential subject (containing no properties, not even an id property) is
    /// considered invalid, as the VC Data Model defines the value of the
    /// [credentialSubject](https://www.w3.org/TR/vc-data-model/#credential-subject) property as
    /// "a set of objects that contain one or more properties [...]"
    pub fn is_empty(&self) -> bool {
        self.id.is_none()
            && match self.property_set {
                Some(ref ps) => ps.is_empty(),
                None => true,
            }
    }
}
