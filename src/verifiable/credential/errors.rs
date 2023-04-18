use thiserror::Error;

/// Error type for `ssi`.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
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
    #[error("Unsupported verification relationship")]
    UnsupportedVerificationRelationship,
    #[error("Empty credential subject")]
    EmptyCredentialSubject,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl From<Error> for String {
    fn from(err: Error) -> String {
        err.to_string()
    }
}
