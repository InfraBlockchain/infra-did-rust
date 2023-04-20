use serde::{Deserialize, Serialize};

use crate::{
    crypto::keytype::KeyType,
    verifiable::credential::{
        contexts::Contexts,
        errors::Error,
        one_or_many::OneOrMany,
        proof::{Proof, ProofSuiteType, VerificationRelationship},
        string_or_uri::StringOrURI,
    },
};

use super::{credential_or_jwt::CredentialOrJWT, holder::Holder};

pub const DEFAULT_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";

// work around https://github.com/w3c/vc-test-suite/issues/103
pub const ALT_DEFAULT_CONTEXT: &str = "https://w3.org/2018/credentials/v1";

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Presentation {
    #[serde(rename = "@context")]
    pub context: Contexts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<StringOrURI>,
    #[serde(rename = "type")]
    pub type_: OneOrMany<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifiable_credential: Option<OneOrMany<CredentialOrJWT>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<OneOrMany<Proof>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<Holder>,
}

impl Presentation {
    pub fn from_json(s: &str) -> Result<Self, Error> {
        let vp: Self = serde_json::from_str(s)?;
        vp.validate()?;
        Ok(vp)
    }

    pub fn from_json_unsigned(s: &str) -> Result<Self, Error> {
        let vp: Self = serde_json::from_str(s)?;
        vp.validate_unsigned()?;
        Ok(vp)
    }

    pub fn validate_unsigned(&self) -> Result<(), Error> {
        if !self.type_.contains(&"VerifiablePresentation".to_string()) {
            return Err(Error::MissingTypeVerifiablePresentation);
        }

        for ref vc in self.verifiable_credential.iter().flatten() {
            match vc {
                CredentialOrJWT::Credential(vc) => {
                    vc.validate_unsigned_embedded()?;
                }
            };
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), Error> {
        self.validate_unsigned()?;

        if self.proof.is_none() {
            return Err(Error::MissingProof);
        }

        Ok(())
    }

    pub fn generate_proof(&self, keypair: KeyType) -> Result<Proof, Error> {
        let message = serde_json::to_string(&self).unwrap();
        let holder = self.holder.as_ref().unwrap().get_id_ref().clone();

        match keypair {
            KeyType::Ed25519(keypair) => {
                let signature = keypair.sign(&message.as_bytes());
                let sig_multibase = multibase::encode(multibase::Base::Base58Btc, signature);

                let mut proof: Proof = Proof::new(ProofSuiteType::Ed25519Signature2018);
                proof.proof_purpose = Some(VerificationRelationship::AssertionMethod);
                proof.verification_method = Some(holder.to_string().to_owned() + "#keys-1");
                proof.proof_value = Some(sig_multibase);
                Ok(proof)
            }
            KeyType::Sr25519(keypair) => {
                let signature = keypair.sign(&message.as_bytes());
                let sig_multibase = multibase::encode(multibase::Base::Base58Btc, signature);

                let mut proof: Proof = Proof::new(ProofSuiteType::Sr25519VerificationKey2020);
                proof.proof_purpose = Some(VerificationRelationship::AssertionMethod);
                proof.verification_method = Some(holder.to_string().to_owned() + "#keys-1");
                proof.proof_value = Some(sig_multibase);
                Ok(proof)
            }
        }
    }

    pub fn add_proof(&mut self, proof: Proof) {
        self.proof = match self.proof.take() {
            None => Some(OneOrMany::One(proof)),
            Some(OneOrMany::One(existing_proof)) => {
                Some(OneOrMany::Many(vec![existing_proof, proof]))
            }
            Some(OneOrMany::Many(mut proofs)) => {
                proofs.push(proof);
                Some(OneOrMany::Many(proofs))
            }
        }
    }

    pub fn verify(&self, keypair: &KeyType) -> Result<bool, Error> {
        if self.proof.is_none() {
            return Err(Error::MissingProof);
        }

        let mut vp_copy = self.clone();
        let proofs = vp_copy.proof.take().unwrap();
        vp_copy.proof = None;
        let message = serde_json::to_string(&vp_copy).unwrap();

        let vcs = vp_copy.verifiable_credential.take().unwrap();

        for vc in vcs {
            match vc {
                CredentialOrJWT::Credential(vc) => {
                    let verify = vc.verify(&keypair)?;
                    if !verify {
                        return Ok(false);
                    }
                }
            };
        }

        for proof in proofs {
            let sig_multibase = proof.proof_value.unwrap();
            match &keypair {
                KeyType::Ed25519(keypair) => {
                    let (_base, sig) = multibase::decode(sig_multibase).unwrap();
                    let verify = keypair.verify_signature(&message.as_bytes(), &sig);
                    if !verify {
                        return Ok(false);
                    }
                }
                KeyType::Sr25519(keypair) => {
                    let (_base, sig) = multibase::decode(sig_multibase).unwrap();
                    let verify = keypair.verify_signature(&message.as_bytes(), &sig).unwrap();
                    if !verify {
                        return Ok(false);
                    }
                }
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::{ed25519::Ed25519KeyPair, sr25519::Sr25519KeyPair},
        verifiable::credential::{contexts::Context, credential::Credential, uri::URI},
    };

    use super::*;

    #[test]
    fn test_sign_presentation_ed25519() {
        let secret_key_bytes = [
            203, 83, 75, 248, 221, 21, 169, 1, 238, 68, 44, 174, 81, 11, 36, 111, 94, 148, 36, 125,
            115, 87, 11, 234, 71, 224, 170, 133, 153, 89, 196, 18,
        ];
        let keypair = KeyType::Ed25519(Ed25519KeyPair::from_secret_key_bytes(&secret_key_bytes));

        let vc_str = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:foo",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let mut vc: Credential = Credential::from_json_unsigned(vc_str).unwrap();
        let proof = vc.generate_proof(&keypair).unwrap();
        vc.add_proof(proof);

        let mut vp = Presentation {
            context: Contexts::Many(vec![Context::URI(URI::String(DEFAULT_CONTEXT.to_string()))]),
            id: Some("http://example.org/presentations/3731".try_into().unwrap()),
            type_: OneOrMany::One("VerifiablePresentation".to_string()),
            verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(vc))),
            proof: None,
            holder: Some(Holder::URI(URI::String("did:example:foo".to_string()))),
        };

        let vp_proof = vp.generate_proof(keypair).unwrap();
        vp.add_proof(vp_proof);
        println!("{:?}", serde_json::to_string(&vp).unwrap());
    }

    #[test]
    fn test_verify_presentation_ed25519() {
        let public_key_bytes = [
            184, 96, 68, 197, 81, 228, 13, 193, 222, 132, 170, 137, 194, 220, 242, 118, 87, 164,
            62, 5, 16, 241, 78, 147, 136, 193, 16, 10, 118, 249, 78, 92,
        ];
        let keypair = KeyType::Ed25519(Ed25519KeyPair::from_public_key_bytes(&public_key_bytes));

        let vp_str = r###"{
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "http://example.org/presentations/3731",
            "type": "VerifiablePresentation",
            "verifiableCredential": {
                "@context": "https://www.w3.org/2018/credentials/v1",
                "id": "http://example.org/credentials/3731",
                "type": [
                    "VerifiableCredential"
                ],
                "credentialSubject": {
                    "id": "did:example:d23dd687a7dc6787646f2eb98d0"
                },
                "issuer": "did:example:foo",
                "issuanceDate": "2020-08-19T21:41:50Z",
                "proof": {
                    "type": "Ed25519Signature2018",
                    "created": "2023-04-20T00:34:38.630560Z",
                    "proofPurpose": "assertionMethod",
                    "proofValue": "z2xmAbSm5FaXWhG8kMUb4rZenKx1SVR2R8R6Wdf9tnowBwJk3F4uaXN1Ufiqd2C85hmeXJhp9ScPC64mHCLwqXV2p",
                    "verificationMethod": "did:example:foo#keys-1"
                }
            },
            "proof": {
                "type": "Ed25519Signature2018",
                "created": "2023-04-20T00:34:38.630648Z",
                "proofPurpose": "assertionMethod",
                "proofValue": "z45VdxhaYSg4FtgdfJcaw4D44tSTZwCmJM5aKccj6qNLNCAuuLPc6nMEGvHwqYkvEUCZbHZX4eyyzfDxqt2ji1mKq",
                "verificationMethod": "did:example:foo#keys-1"
            },
            "holder": "did:example:foo"
        }"###;

        let vp: Presentation = Presentation::from_json(vp_str).unwrap();

        assert_eq!(vp.verify(&keypair).unwrap(), true);
    }

    #[test]
    fn test_sign_presentation_sr25519() {
        let secret_key_bytes = [
            203, 83, 75, 248, 221, 21, 169, 1, 238, 68, 44, 174, 81, 11, 36, 111, 94, 148, 36, 125,
            115, 87, 11, 234, 71, 224, 170, 133, 153, 89, 196, 18,
        ];
        let keypair = KeyType::Sr25519(
            Sr25519KeyPair::from_mini_secret_key_bytes(&secret_key_bytes).unwrap(),
        );

        let vc_str = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:foo",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let mut vc: Credential = Credential::from_json_unsigned(vc_str).unwrap();
        let proof = vc.generate_proof(&keypair).unwrap();
        vc.add_proof(proof);

        let mut vp = Presentation {
            context: Contexts::Many(vec![Context::URI(URI::String(DEFAULT_CONTEXT.to_string()))]),
            id: Some("http://example.org/presentations/3731".try_into().unwrap()),
            type_: OneOrMany::One("VerifiablePresentation".to_string()),
            verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(vc))),
            proof: None,
            holder: Some(Holder::URI(URI::String("did:example:foo".to_string()))),
        };

        let vp_proof = vp.generate_proof(keypair).unwrap();
        vp.add_proof(vp_proof);
        println!("{:?}", serde_json::to_string(&vp).unwrap());
    }

    #[test]
    fn test_verify_presentation_sr25519() {
        let public_key_bytes = [
            10, 134, 93, 127, 235, 233, 183, 168, 140, 74, 140, 108, 193, 62, 52, 75, 186, 199, 87,
            11, 57, 197, 167, 7, 79, 249, 198, 238, 217, 121, 191, 22,
        ];
        let keypair =
            KeyType::Sr25519(Sr25519KeyPair::from_public_key_bytes(&public_key_bytes).unwrap());

        let vp_str = r###"{
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "id": "http://example.org/presentations/3731",
            "type": "VerifiablePresentation",
            "verifiableCredential": {
                "@context": "https://www.w3.org/2018/credentials/v1",
                "id": "http://example.org/credentials/3731",
                "type": [
                    "VerifiableCredential"
                ],
                "credentialSubject": {
                    "id": "did:example:d23dd687a7dc6787646f2eb98d0"
                },
                "issuer": "did:example:foo",
                "issuanceDate": "2020-08-19T21:41:50Z",
                "proof": {
                    "type": "Sr25519VerificationKey2020",
                    "created": "2023-04-20T00:36:34.144078Z",
                    "proofPurpose": "assertionMethod",
                    "proofValue": "z3cJ7r7iDM9vjTG3Z3F7Q5kJEUihrj9EL4Nj4Ms4rAC5M4UWi6zQfZ5iG8YjAqgvULGxD9YH3kV26knR3Uk2Ds1YQ",
                    "verificationMethod": "did:example:foo#keys-1"
                }
            },
            "proof": {
                "type": "Sr25519VerificationKey2020",
                "created": "2023-04-20T00:36:34.144147Z",
                "proofPurpose": "assertionMethod",
                "proofValue": "zCz4tUxJc6PF5GdLGweaxxYgYWGLYhCcAEytGcmQkx2cdWtnmoGYeznwjRdBw7RhvCyQ7H41oFKwE9zRfVoyfPYu",
                "verificationMethod": "did:example:foo#keys-1"
            },
            "holder": "did:example:foo"
        }"###;

        let vp: Presentation = Presentation::from_json(vp_str).unwrap();

        assert_eq!(vp.verify(&keypair).unwrap(), true);
    }
}
