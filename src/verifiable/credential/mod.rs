use ssi::jwk::{Base64urlUInt, OctetParams, Params, JWK};
use ssi_ldp::{ProofSuite, ProofSuiteType};
use ssi_vc::{Credential, LinkedDataProofOptions, ProofPurpose, URI};

use crate::{crypto::ed25519::Ed25519KeyPair, resolver::resolver::InfraDIDResolver};

pub async fn issue_credential(
    did: String,
    hex_secret_key: String,
    credential_string: String,
) -> String {
    let secret_key_bytes = match hex::decode(hex_secret_key) {
        Ok(bytes) => bytes,
        Err(error) => {
            panic!("There was a problem convert secret key bytes: {:?}", error)
        }
    };

    let keypair = Ed25519KeyPair::from_secret_key_bytes(&secret_key_bytes);

    let key: JWK = JWK::from(Params::OKP(OctetParams {
        curve: "Ed25519".to_string(),
        public_key: Base64urlUInt(keypair.to_public_key_bytes().to_vec()),
        private_key: Some(Base64urlUInt(keypair.to_secret_key_bytes().to_vec())),
    }));

    let mut vc: Credential = Credential::from_json_unsigned(credential_string.as_str()).unwrap();

    let resolver = InfraDIDResolver::default();

    let mut context_loader = ssi_json_ld::ContextLoader::default();
    let issue_options: LinkedDataProofOptions = LinkedDataProofOptions {
        type_: Some(ProofSuiteType::Ed25519Signature2020),
        proof_purpose: Some(ProofPurpose::AssertionMethod),
        verification_method: Some(URI::String(did + "#keys-2")),
        ..Default::default()
    };

    let proof = ProofSuiteType::Ed25519Signature2020
        .sign(
            &vc,
            &issue_options,
            &resolver,
            &mut context_loader,
            &key,
            None,
        )
        .await
        .unwrap();
    vc.add_proof(proof);
    vc.validate().unwrap();

    let verification_result = vc.verify(None, &resolver, &mut context_loader).await;
    assert!(verification_result.errors.is_empty());
    serde_json::to_string_pretty(&vc).unwrap()
}

pub async fn verify_credential(credential_string: String) -> String {
    let vc: Credential = Credential::from_json(credential_string.as_str()).unwrap();
    let issuer = vc.clone().issuer.unwrap();
    let resolver = InfraDIDResolver::default();

    let mut context_loader = ssi_json_ld::ContextLoader::default();

    let options: LinkedDataProofOptions = LinkedDataProofOptions {
        proof_purpose: Some(ProofPurpose::AssertionMethod),
        verification_method: Some(URI::String(issuer.get_id() + "#keys-2")),
        ..Default::default()
    };

    let verification_result = vc
        .verify(Some(options), &resolver, &mut context_loader)
        .await;
    if verification_result.errors.is_empty() {
        "true".to_string()
    } else {
        "false".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn test_sign_credential_ed25519() {
        let did = "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW".to_string();
        let hex_secret_key =
            "8006aaa5985f1d72e916167bdcbc663232cef5823209b1246728f73137888170".to_string();
        let vc_str = r###"{
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "did:infra:space:5FDseiC76zPek2YYkuyenu4ZgxZ7PUWXt9d19HNB5CaQXt5U",
            "type": [
                "VerifiableCredential"
            ],
            "credentialSubject": [
                {
                    "id": "did:example:d23dd687a7dc6787646f2eb98d0"
                }
            ],
            "issuanceDate": "2023-04-24T06:08:03.039Z",
            "issuer": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW"
        }"###;

        let vc = issue_credential(did, hex_secret_key, vc_str.to_string()).await;
        println!("{:?}", vc);
    }

    #[async_std::test]
    async fn test_verify_credential_ed25519() {
        let vc_str = r###"{
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "did:infra:space:5FDseiC76zPek2YYkuyenu4ZgxZ7PUWXt9d19HNB5CaQXt5U",
            "type": [
                "VerifiableCredential"
            ],
            "credentialSubject": [
                {
                    "id": "did:example:d23dd687a7dc6787646f2eb98d0"
                }
            ],
            "issuer": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW",
            "issuanceDate": "2023-04-24T06:08:03.039Z",
            "proof": {
                "@context": [
                    "https://w3id.org/security/suites/ed25519-2020/v1"
                ],
                "type": "Ed25519Signature2020",
                "proofPurpose": "assertionMethod",
                "proofValue": "z3gFJvCvNYTVQJ7R7tXzbmAyZ62g3ZymbzwTrWJhgwatJouope5GnQmz7NW2zAVVYbor5KUW8TUa1V5KADPp8kBog",
                "verificationMethod": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW#keys-2",
                "created": "2023-04-25T23:52:13.770Z"
            }
        }"###;

        let verify = verify_credential(vc_str.to_string()).await;
        assert_eq!(verify, "true".to_string());
    }
}
