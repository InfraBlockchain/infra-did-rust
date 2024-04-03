use async_trait::async_trait;
use serde_json::json;
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, TYPE_DID_LD_JSON,
};
use ssi::jwk::{Base64urlUInt, OctetParams, Params, JWK};
use ssi_dids::{Document, VerificationMethod, VerificationMethodMap, DIDURL};

use crate::did::{did_to_hex_public_key, AddressType};

const DID_KEY_ED25519_PREFIX: [u8; 2] = [0xed, 0x01];

pub const ERROR_NOT_FOUND: &str = "notFound";
const DOC_JSON_FOO: &str = include_str!("../../tests/did-example-foo.json");
const DOC_JSON_INFRA: &str = include_str!("../../tests/did-infra-space.json");

/// A DID Resolver implementing a client for the [DID Resolution HTTP(S)
/// Binding](https://w3c-ccg.github.io/did-resolution/#bindings-https).
#[derive(Debug, Clone, Default)]
pub struct InfraDIDResolver {
    /// HTTP(S) URL for DID resolver HTTP(S) endpoint.
    pub endpoint: String,
}

impl InfraDIDResolver {
    /// Construct a new HTTP DID Resolver with a given [endpoint][InfraDIDResolver::endpoint] URL.
    pub fn new(url: &str) -> Self {
        Self {
            endpoint: url.to_string(),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DIDResolver for InfraDIDResolver {
    /// Resolve a DID over HTTP(S), using the [DID Resolution HTTP(S) Binding](https://w3c-ccg.github.io/did-resolution/#bindings-https).
    async fn resolve(
        &self,
        did: &str,
        _input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let hex_public_key = did_to_hex_public_key(did.to_string(), AddressType::Ed25519).unwrap();
        let public_key_bytes = hex::decode(hex_public_key).unwrap();

        let jwk: JWK = JWK::from(Params::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(public_key_bytes.clone()),
            private_key: None,
        }));

        let vms = vec![
            VerificationMethod::Map(VerificationMethodMap {
                id: did.to_string() + "#keys-1",
                type_: "Ed25519VerificationKey2018".to_string(),
                controller: did.to_string(),
                public_key_base58: Some(bs58::encode(public_key_bytes.clone()).into_string()),
                ..Default::default()
            }),
            VerificationMethod::Map(VerificationMethodMap {
                id: did.to_string() + "#keys-2",
                type_: "Ed25519VerificationKey2020".to_string(),
                controller: did.to_string(),
                property_set: serde_json::from_value(json!({
                    "publicKeyMultibase": multibase::encode(
                        multibase::Base::Base58Btc,
                        [
                            DID_KEY_ED25519_PREFIX.to_vec(),
                            public_key_bytes.clone()
                        ]
                        .concat()
                    ),
                }))
                .unwrap(),
                ..Default::default()
            }),
            VerificationMethod::Map(VerificationMethodMap {
                id: did.to_string() + "#keys-3",
                type_: "JsonWebKey2020".to_string(),
                controller: did.to_string(),
                public_key_jwk: Some(jwk),
                ..Default::default()
            }),
        ];

        let vm_urls = vec![
            VerificationMethod::DIDURL(DIDURL {
                did: did.to_string() + "#keys-1",
                ..Default::default()
            }),
            VerificationMethod::DIDURL(DIDURL {
                did: did.to_string() + "#keys-2",
                ..Default::default()
            }),
            VerificationMethod::DIDURL(DIDURL {
                did: did.to_string() + "#keys-3",
                ..Default::default()
            }),
        ];

        let doc = Document {
            context: ssi_dids::Contexts::One(ssi_dids::Context::URI(
                ssi_dids::DEFAULT_CONTEXT.into(),
            )),
            id: did.to_string(),
            verification_method: Some(vms),
            authentication: Some(vm_urls.clone()),
            assertion_method: Some(vm_urls),
            ..Default::default()
        };
        (
            ResolutionMetadata {
                error: None,
                content_type: Some(TYPE_DID_LD_JSON.to_string()),
                property_set: None,
            },
            Some(doc),
            Some(DocumentMetadata::default()),
        )
    }
}

/// A DID Resolver implementing a client for the [DID Resolution HTTP(S)
/// Binding](https://w3c-ccg.github.io/did-resolution/#bindings-https).
#[derive(Debug, Clone, Default)]
pub struct TestDIDResolver {
    /// HTTP(S) URL for DID resolver HTTP(S) endpoint.
    pub endpoint: String,
}

impl TestDIDResolver {
    /// Construct a new HTTP DID Resolver with a given [endpoint][HTTPDIDResolver::endpoint] URL.
    pub fn new(url: &str) -> Self {
        Self {
            endpoint: url.to_string(),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DIDResolver for TestDIDResolver {
    /// Resolve a DID over HTTP(S), using the [DID Resolution HTTP(S) Binding](https://w3c-ccg.github.io/did-resolution/#bindings-https).
    async fn resolve(
        &self,
        did: &str,
        _input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let doc_str = match did {
            "did:example:foo" => DOC_JSON_FOO,
            "did:infra:01:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW" => DOC_JSON_INFRA,
            _ => return (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None),
        };
        let doc: Document = match serde_json::from_str(doc_str) {
            Ok(doc) => doc,
            Err(err) => {
                return (ResolutionMetadata::from_error(&err.to_string()), None, None);
            }
        };
        (
            ResolutionMetadata {
                error: None,
                content_type: Some(TYPE_DID_LD_JSON.to_string()),
                property_set: None,
            },
            Some(doc),
            Some(DocumentMetadata::default()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn test_resolve() {
        let resolver = TestDIDResolver::default();
        let (_, doc, _) = resolver
            .resolve("did:example:foo", &ResolutionInputMetadata::default())
            .await;
        println!("{:?}", serde_json::to_string_pretty(&doc).unwrap());
    }

    #[async_std::test]
    async fn test_infra_resolve() {
        let resolver = InfraDIDResolver::default();
        let (_, doc, _) = resolver
            .resolve(
                "did:infra:01:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW",
                &ResolutionInputMetadata::default(),
            )
            .await;
        println!("{:?}", serde_json::to_string_pretty(&doc).unwrap());
    }
}
