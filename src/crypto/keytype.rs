use super::{ed25519::Ed25519KeyPair, sr25519::Sr25519KeyPair};

pub enum KeyType {
    Ed25519(Ed25519KeyPair),
    Sr25519(Sr25519KeyPair),
}
