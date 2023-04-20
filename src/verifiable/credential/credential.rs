use serde::{Deserialize, Serialize};

use crate::{crypto::keytype::KeyType, verifiable::credential::proof::ProofSuiteType};

use super::{
    contexts::Contexts,
    credential_subject::CredentialSubject,
    errors::Error,
    issuer::Issuer,
    one_or_many::OneOrMany,
    proof::{Proof, VerificationRelationship},
    schema::Schema,
    string_or_uri::StringOrURI,
    vc_date_time::VCDateTime,
};

pub const DEFAULT_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";

// work around https://github.com/w3c/vc-test-suite/issues/103
pub const ALT_DEFAULT_CONTEXT: &str = "https://w3.org/2018/credentials/v1";

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    #[serde(rename = "@context")]
    pub context: Contexts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<StringOrURI>,
    #[serde(rename = "type")]
    pub type_: OneOrMany<String>,
    pub credential_subject: OneOrMany<CredentialSubject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<Issuer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuance_date: Option<VCDateTime>,
    // This field is populated only when using
    // embedded proofs such as LD-PROOF
    //   https://w3c-ccg.github.io/ld-proofs/
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<OneOrMany<Proof>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<VCDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<OneOrMany<Schema>>,
}

impl Credential {
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

    pub fn validate(&self) -> Result<(), Error> {
        self.validate_unsigned()?;
        if self.proof.is_none() {
            return Err(Error::MissingProof);
        }
        Ok(())
    }

    pub fn validate_unsigned(&self) -> Result<(), Error> {
        if !self.type_.contains(&"VerifiableCredential".to_string()) {
            return Err(Error::MissingTypeVerifiableCredential);
        }
        if self.issuer.is_none() {
            return Err(Error::InvalidIssuer);
        }
        if self.credential_subject.is_empty() {
            // https://www.w3.org/TR/vc-data-model/#credential-subject
            // VC-Data-Model "defines a credentialSubject property for the expression of claims
            // about one or more subjects."
            // Therefore, zero credentialSubject values is considered invalid.
            return Err(Error::EmptyCredentialSubject);
        }
        for subject in &self.credential_subject {
            if subject.is_empty() {
                return Err(Error::EmptyCredentialSubject);
            }
        }
        if self.issuance_date.is_none() {
            return Err(Error::MissingIssuanceDate);
        }

        Ok(())
    }

    pub(crate) fn validate_unsigned_embedded(&self) -> Result<(), Error> {
        self.validate_unsigned()?;
        Ok(())
    }

    pub fn generate_proof(&self, keypair: &KeyType) -> Result<Proof, Error> {
        let message = serde_json::to_string(&self).unwrap();
        let issuer = self.issuer.as_ref().unwrap().get_id_ref().clone();

        match keypair {
            KeyType::Ed25519(keypair) => {
                let signature = keypair.sign(&message.as_bytes());
                let sig_multibase = multibase::encode(multibase::Base::Base58Btc, signature);

                let mut proof: Proof = Proof::new(ProofSuiteType::Ed25519Signature2018);
                proof.proof_purpose = Some(VerificationRelationship::AssertionMethod);
                proof.verification_method = Some(issuer.to_string().to_owned() + "#keys-1");
                proof.proof_value = Some(sig_multibase);
                Ok(proof)
            }
            KeyType::Sr25519(keypair) => {
                let signature = keypair.sign(&message.as_bytes());
                let sig_multibase = multibase::encode(multibase::Base::Base58Btc, signature);

                let mut proof: Proof = Proof::new(ProofSuiteType::Sr25519VerificationKey2020);
                proof.proof_purpose = Some(VerificationRelationship::AssertionMethod);
                proof.verification_method = Some(issuer.to_string().to_owned() + "#keys-1");
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

        let mut vc_copy = self.clone();
        let proofs = vc_copy.proof.take().unwrap();
        vc_copy.proof = None;
        let message = serde_json::to_string(&vc_copy).unwrap();

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
    use crate::crypto::{ed25519::Ed25519KeyPair, sr25519::Sr25519KeyPair};

    use super::*;

    #[test]
    fn test_sign_credential_ed25519() {
        let keypair_bytes = [
            203, 83, 75, 248, 221, 21, 169, 1, 238, 68, 44, 174, 81, 11, 36, 111, 94, 148, 36, 125,
            115, 87, 11, 234, 71, 224, 170, 133, 153, 89, 196, 18,
        ];
        let keypair = KeyType::Ed25519(Ed25519KeyPair::from_secret_key_bytes(&keypair_bytes));

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
        println!("{:?}", serde_json::to_string(&vc).unwrap());
    }

    #[test]
    fn test_verify_credential_ed25519() {
        let keypair_bytes = [
            184, 96, 68, 197, 81, 228, 13, 193, 222, 132, 170, 137, 194, 220, 242, 118, 87, 164,
            62, 5, 16, 241, 78, 147, 136, 193, 16, 10, 118, 249, 78, 92,
        ];
        let keypair = KeyType::Ed25519(Ed25519KeyPair::from_public_key_bytes(&keypair_bytes));

        let vc_str = r###"{
            "@context":"https://www.w3.org/2018/credentials/v1",
            "id":"http://example.org/credentials/3731",
            "type":[
               "VerifiableCredential"
            ],
            "credentialSubject":{
               "id":"did:example:d23dd687a7dc6787646f2eb98d0"
            },
            "issuer":"did:example:foo",
            "issuanceDate":"2020-08-19T21:41:50Z",
            "proof":{
               "type":"Ed25519Signature2018",
               "created":"2023-04-18T01:08:19.517433Z",
               "proofPurpose":"assertionMethod",
               "proofValue":"z2xmAbSm5FaXWhG8kMUb4rZenKx1SVR2R8R6Wdf9tnowBwJk3F4uaXN1Ufiqd2C85hmeXJhp9ScPC64mHCLwqXV2p",
               "verificationMethod":"did:infra:01:5GETGN5ksMY586q4EdjQap6YeSbu8tKENJ58Wx3vBkgHs8B2#keys-1"
            }
         }"###;

        let vc: Credential = Credential::from_json(vc_str).unwrap();

        assert_eq!(vc.verify(&keypair).unwrap(), true);
    }

    #[test]
    fn test_sign_credential_sr25519() {
        let keypair_bytes = [
            203, 83, 75, 248, 221, 21, 169, 1, 238, 68, 44, 174, 81, 11, 36, 111, 94, 148, 36, 125,
            115, 87, 11, 234, 71, 224, 170, 133, 153, 89, 196, 18,
        ];
        let keypair =
            KeyType::Sr25519(Sr25519KeyPair::from_mini_secret_key_bytes(&keypair_bytes).unwrap());

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
        println!("{:?}", serde_json::to_string(&vc).unwrap());
    }

    #[test]
    fn test_verify_credential_sr25519() {
        let keypair_bytes = [
            10, 134, 93, 127, 235, 233, 183, 168, 140, 74, 140, 108, 193, 62, 52, 75, 186, 199, 87,
            11, 57, 197, 167, 7, 79, 249, 198, 238, 217, 121, 191, 22,
        ];
        let keypair =
            KeyType::Sr25519(Sr25519KeyPair::from_public_key_bytes(&keypair_bytes).unwrap());

        let vc_str = r###"{
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
                "created": "2023-04-19T23:53:37.394517Z",
                "proofPurpose": "assertionMethod",
                "proofValue": "zHk9DkopSPjHeJiDsVWLNHUMdgbMAvjt7MU9pjKTzi7tcw3eam7guUdiGjRQDjPDreAWaCuJSdhsYWuu2Ki2YZa8",
                "verificationMethod": "did:example:foo#keys-1"
            }
        }"###;

        let vc: Credential = Credential::from_json(vc_str).unwrap();

        assert_eq!(vc.verify(&keypair).unwrap(), true);
    }
}
