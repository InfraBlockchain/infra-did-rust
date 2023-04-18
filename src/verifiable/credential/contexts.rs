use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap as Map;

use super::{
    credential::{ALT_DEFAULT_CONTEXT, DEFAULT_CONTEXT},
    one_or_many::OneOrMany,
    uri::URI,
};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum Context {
    URI(URI),
    Object(Map<String, Value>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
#[serde(try_from = "OneOrMany<Context>")]
pub enum Contexts {
    One(Context),
    Many(Vec<Context>),
}

impl TryFrom<OneOrMany<Context>> for Contexts {
    type Error = String;
    fn try_from(context: OneOrMany<Context>) -> Result<Self, Self::Error> {
        let first_uri = match context.first() {
            None => return Err("Missing Context".to_string()),
            Some(Context::URI(URI::String(uri))) => uri,
            Some(Context::Object(_)) => return Err("Invalid Context".to_string()),
        };
        if first_uri != DEFAULT_CONTEXT && first_uri != ALT_DEFAULT_CONTEXT {
            return Err("Invalid Context".to_string());
        }
        Ok(match context {
            OneOrMany::One(context) => Contexts::One(context),
            OneOrMany::Many(contexts) => Contexts::Many(contexts),
        })
    }
}

impl From<Contexts> for OneOrMany<Context> {
    fn from(contexts: Contexts) -> OneOrMany<Context> {
        match contexts {
            Contexts::One(context) => OneOrMany::One(context),
            Contexts::Many(contexts) => OneOrMany::Many(contexts),
        }
    }
}

impl Contexts {
    /// Check if the contexts contains the given URI.
    pub fn contains_uri(&self, uri: &str) -> bool {
        match self {
            Self::One(context) => {
                if let Context::URI(URI::String(context_uri)) = context {
                    if context_uri == uri {
                        return true;
                    }
                }
            }
            Self::Many(contexts) => {
                for context in contexts {
                    if let Context::URI(URI::String(context_uri)) = context {
                        if context_uri == uri {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
}
