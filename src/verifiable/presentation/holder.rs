use serde::{Deserialize, Serialize};

use crate::verifiable::credential::{object_with_id::ObjectWithId, uri::URI};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Holder {
    URI(URI),
    Object(ObjectWithId),
}

impl Holder {
    /// Return this holder's id URI
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
