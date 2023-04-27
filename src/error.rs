use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    LDP(#[from] ssi_ldp::Error),
    #[error(transparent)]
    JWS(#[from] ssi_jws::Error),
    #[error(transparent)]
    DID(#[from] ssi_dids::Error),
    #[error(transparent)]
    VC(#[from] ssi_vc::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    #[error(transparent)]
    Mnemonic(#[from] anyhow::Error),
    #[error(transparent)]
    Ed25519(#[from] ed25519_dalek::ed25519::Error),
    #[error(transparent)]
    Base58(#[from] bs58::decode::Error),
    #[error("Invalid DID")]
    InvalidDID,
    #[error("Invalid Keypair")]
    InvalidKeypair,
    #[error("Invalid Secret key")]
    InvalidSecretKey,
    #[error("Invalid Proof")]
    InvalidProof,
    #[error("Missing proof")]
    MissingProof,
    #[error("Missing credential schema")]
    MissingCredentialSchema,
    #[error("Missing credential")]
    MissingCredential,
    #[error("Missing presentation")]
    MissingPresentation,
    #[error("Invalid issuer")]
    InvalidIssuer,
    #[error("Missing holder property")]
    MissingHolder,
    #[error("Unsupported Holder Binding")]
    UnsupportedHolderBinding,
    #[error("Missing issuance date")]
    MissingIssuanceDate,
    #[error("Missing type VerifiableCredential")]
    MissingTypeVerifiableCredential,
    #[error("Missing type VerifiablePresentation")]
    MissingTypeVerifiablePresentation,
    #[error("Invalid subject")]
    InvalidSubject,
    #[error("Unable to convert date/time")]
    TimeError,
    #[error("Empty credential subject")]
    EmptyCredentialSubject,
    /// Verification method id does not match JWK id
    #[error("Verification method id does not match JWK id. VM id: {0}, JWK key id: {1}")]
    KeyIdVMMismatch(String, String),
    /// Linked data proof option unencodable as JWT claim
    #[error("Linked data proof option unencodable as JWT claim: {0}")]
    UnencodableOptionClaim(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
