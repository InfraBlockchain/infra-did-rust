use serde::{Deserialize, Serialize};

use super::{object_with_id::ObjectWithId, uri::URI};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Issuer {
    URI(URI),
    Object(ObjectWithId),
}

impl Issuer {
    /// Return this issuer's id URI
    pub fn get_id(&self) -> String {
        match self {
            Self::URI(uri) => uri.to_string(),
            Self::Object(object_with_id) => object_with_id.id.to_string(),
        }
    }
    pub fn get_id_ref(&self) -> &str {
        match self {
            Self::URI(uri) => uri.as_str(),
            Self::Object(object_with_id) => object_with_id.id.as_str(),
        }
    }
}
