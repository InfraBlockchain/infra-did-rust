use ssi::jwk::{Base64urlUInt, OctetParams, Params, JWK};
use ssi_ldp::ProofSuiteType;
use ssi_vc::{
    Credential, CredentialOrJWT, LinkedDataProofOptions, OneOrMany, Presentation, ProofPurpose,
    StringOrURI, DEFAULT_CONTEXT, URI,
};

use crate::{
    crypto::ed25519::Ed25519KeyPair, did::random_phrase, resolver::resolver::InfraDIDResolver,
};

pub async fn issue_presentation(
    did: String,
    hex_secret_key: String,
    credential_string: String,
) -> String {
    let secret_key_bytes = hex::decode(hex_secret_key).unwrap();

    let keypair = Ed25519KeyPair::from_secret_key_bytes(&secret_key_bytes);

    let key: JWK = JWK::from(Params::OKP(OctetParams {
        curve: "Ed25519".to_string(),
        public_key: Base64urlUInt(keypair.to_public_key_bytes().to_vec()),
        private_key: Some(Base64urlUInt(keypair.to_secret_key_bytes().to_vec())),
    }));

    let vc: Credential = Credential::from_json(credential_string.as_str()).unwrap();

    let resolver = InfraDIDResolver::default();

    let id = {
        let mnemonic = random_phrase(12);
        let keypair: Ed25519KeyPair =
            Ed25519KeyPair::from_bip39_phrase(mnemonic.as_str(), Some(""));
        let address = keypair.ss58_address(42);
        let did = format!("did:infra:{}:{}", "01", address.clone());
        did
    };

    let mut vp = Presentation {
        context: ssi_vc::Contexts::Many(vec![ssi_vc::Context::URI(ssi_vc::URI::String(
            DEFAULT_CONTEXT.to_string(),
        ))]),
        id: Some(StringOrURI::String(id.to_string())),
        type_: OneOrMany::One("VerifiablePresentation".to_string()),
        verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(vc))),
        proof: None,
        holder: Some(URI::String(did.to_string())),
        property_set: None,
        holder_binding: None,
    };

    let vp_issue_options: LinkedDataProofOptions = LinkedDataProofOptions {
        type_: Some(ProofSuiteType::Ed25519Signature2020),
        proof_purpose: Some(ProofPurpose::AssertionMethod),
        verification_method: Some(URI::String(did + "#keys-2")),
        ..Default::default()
    };

    let mut context_loader = ssi_json_ld::ContextLoader::default();

    let vp_proof = vp
        .generate_proof(&key, &vp_issue_options, &resolver, &mut context_loader)
        .await
        .unwrap();
    vp.add_proof(vp_proof);
    vp.validate().unwrap();

    let vp_verification_result = vp
        .verify(
            Some(vp_issue_options.clone()),
            &resolver,
            &mut context_loader,
        )
        .await;
    assert!(vp_verification_result.errors.is_empty());

    serde_json::to_string_pretty(&vp).unwrap()
}

pub async fn verify_presentation(presentation_string: String) -> String {
    let vp: Presentation = Presentation::from_json(presentation_string.as_str()).unwrap();
    let holder = vp.clone().holder.unwrap();

    let resolver = InfraDIDResolver::default();

    let mut context_loader = ssi_json_ld::ContextLoader::default();

    let options: LinkedDataProofOptions = LinkedDataProofOptions {
        proof_purpose: Some(ProofPurpose::AssertionMethod),
        verification_method: Some(URI::String(holder.as_str().to_string() + "#keys-2")),
        ..Default::default()
    };

    let vp_verification_result = vp
        .verify(Some(options), &resolver, &mut context_loader)
        .await;

    if vp_verification_result.errors.is_empty() {
        "true".to_string()
    } else {
        "false".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn test_sign_presentation_ed25519() {
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

        let vc = issue_presentation(did, hex_secret_key, vc_str.to_string()).await;
        println!("{:?}", vc);
    }

    #[async_std::test]
    async fn test_verify_presentation_ed25519() {
        let vp_str = r###"{
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "did:infra:01:5C65pZF9tBxUgRarjqNQRLUYaxhjDatawtJsPUFLsv8HrRDs",
            "type": "VerifiablePresentation",
            "verifiableCredential": {
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
            },
            "proof": {
                "@context": [
                    "https://w3id.org/security/suites/ed25519-2020/v1"
                ],
                "type": "Ed25519Signature2020",
                "proofPurpose": "assertionMethod",
                "proofValue": "z5fwTSAD25dFq62rYCzeNUD5TfYwpgSB7HLa9eLtDMpPVB2hb83rbvDmydwPmwubiswWYvcZVmxqG34GxkkLkypDY",
                "verificationMethod": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW#keys-2",
                "created": "2023-04-26T00:21:22.810Z"
            },
            "holder": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW"
        }"###;

        let verify = verify_presentation(vp_str.to_string()).await;
        assert_eq!(verify, "true".to_string());
    }
}
