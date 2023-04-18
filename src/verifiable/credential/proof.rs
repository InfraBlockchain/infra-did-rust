use iref::Iri;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use static_iref::iri;
use std::str::FromStr;

use super::errors::Error;
use super::vc_date_time::VCDateTime;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
// TODO use enum to separate betwen JWS and LD proofs?
// TODO create generics type to allow users to provide their own proof suite that implements ProofSuite
pub struct Proof {
    #[serde(rename = "@context")]
    // TODO: use consistent types for context
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub context: Value,
    #[serde(rename = "type")]
    pub type_: ProofSuiteType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<VCDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_purpose: Option<VerificationRelationship>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,
}

impl Proof {
    pub fn new(type_: ProofSuiteType) -> Self {
        let expected_utc_now = chrono::Utc::now();
        let vc_date_time_now = VCDateTime::from(expected_utc_now);

        Self {
            type_,
            context: Value::default(),
            created: Some(vc_date_time_now),
            proof_purpose: None,
            proof_value: None,
            verification_method: None,
        }
    }
}

/// A [verification relationship](https://w3c.github.io/did-core/#dfn-verification-relationship).
///
/// The relationship between a [verification method][VerificationMethod] and a DID
/// Subject (as described by a [DID Document][Document]) is considered analogous to a [proof
/// purpose](crate::vc::ProofPurpose).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(try_from = "String")]
#[serde(rename_all = "camelCase")]
pub enum VerificationRelationship {
    AssertionMethod,
    Authentication,
    KeyAgreement,
    ContractAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

impl Default for VerificationRelationship {
    fn default() -> Self {
        Self::AssertionMethod
    }
}

impl FromStr for VerificationRelationship {
    type Err = Error;
    fn from_str(purpose: &str) -> Result<Self, Self::Err> {
        match purpose {
            "authentication" => Ok(Self::Authentication),
            "assertionMethod" => Ok(Self::AssertionMethod),
            "keyAgreement" => Ok(Self::KeyAgreement),
            "contractAgreement" => Ok(Self::ContractAgreement),
            "capabilityInvocation" => Ok(Self::CapabilityInvocation),
            "capabilityDelegation" => Ok(Self::CapabilityDelegation),
            _ => Err(Error::UnsupportedVerificationRelationship),
        }
    }
}

impl TryFrom<String> for VerificationRelationship {
    type Error = Error;
    fn try_from(purpose: String) -> Result<Self, Self::Error> {
        Self::from_str(&purpose)
    }
}

impl From<VerificationRelationship> for String {
    fn from(purpose: VerificationRelationship) -> String {
        match purpose {
            VerificationRelationship::Authentication => "authentication".to_string(),
            VerificationRelationship::AssertionMethod => "assertionMethod".to_string(),
            VerificationRelationship::KeyAgreement => "keyAgreement".to_string(),
            VerificationRelationship::ContractAgreement => "contractAgreement".to_string(),
            VerificationRelationship::CapabilityInvocation => "capabilityInvocation".to_string(),
            VerificationRelationship::CapabilityDelegation => "capabilityDelegation".to_string(),
        }
    }
}

impl VerificationRelationship {
    pub fn to_iri(&self) -> Iri<'static> {
        match self {
            VerificationRelationship::Authentication => {
                iri!("https://w3id.org/security#authenticationMethod")
            }
            VerificationRelationship::AssertionMethod => {
                iri!("https://w3id.org/security#assertionMethod")
            }
            VerificationRelationship::KeyAgreement => {
                iri!("https://w3id.org/security#keyAgreementMethod")
            }
            VerificationRelationship::ContractAgreement => {
                iri!("https://w3id.org/security#contractAgreementMethod")
            }
            VerificationRelationship::CapabilityInvocation => {
                iri!("https://w3id.org/security#capabilityInvocationMethod")
            }
            VerificationRelationship::CapabilityDelegation => {
                iri!("https://w3id.org/security#capabilityDelegationMethod")
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum ProofSuiteType {
    Ed25519Signature2018,
    Sr25519VerificationKey2020,
}

impl FromStr for ProofSuiteType {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_value(json!(format!("{s}")))
    }
}
