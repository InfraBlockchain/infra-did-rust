use serde::{Deserialize, Serialize};

use crate::verifiable::credential::credential::Credential;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum CredentialOrJWT {
    Credential(Credential),
    // JWT(String),
}
