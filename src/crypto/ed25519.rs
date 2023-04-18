use base58::ToBase58;
use ed25519_dalek::{
    Keypair, PublicKey, SecretKey, Signature, Signer, Verifier, KEYPAIR_LENGTH, SECRET_KEY_LENGTH,
};
use rand::rngs::OsRng;

pub struct Ed25519KeyPair(ed25519_dalek::Keypair);

impl Ed25519KeyPair {
    pub fn generate() -> Ed25519KeyPair {
        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        Ed25519KeyPair(keypair)
    }

    pub fn from_secret_key_bytes(bytes: &[u8]) -> Ed25519KeyPair {
        let secret_key: SecretKey = SecretKey::from_bytes(bytes).unwrap();
        let public_key: PublicKey = (&secret_key).into();

        let secret = secret_key.to_bytes();
        let public = public_key.to_bytes();

        let mut keypair_bytes: [u8; KEYPAIR_LENGTH] = [0u8; KEYPAIR_LENGTH];

        keypair_bytes[..SECRET_KEY_LENGTH].copy_from_slice(&secret);
        keypair_bytes[SECRET_KEY_LENGTH..].copy_from_slice(&public);

        let keypair = ed25519_dalek::Keypair::from_bytes(&keypair_bytes).ok();
        Ed25519KeyPair(keypair.unwrap())
    }

    pub fn ss58_address(&self, prefix: u8) -> String {
        let mut v = vec![prefix];
        v.extend_from_slice(&self.0.public.to_bytes());
        let r = ss58hash(&v);
        v.extend_from_slice(&r.as_bytes()[0..2]);
        v.to_base58()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let signature: Signature = self.0.sign(message);
        signature
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        let signature = ed25519_dalek::Signature::from_bytes(signature).unwrap();
        let public_key: PublicKey = self.0.public;
        let verified: bool = public_key.verify(message, &signature).is_ok();
        verified
    }
}

fn ss58hash(data: &[u8]) -> blake2_rfc::blake2b::Blake2bResult {
    const PREFIX: &[u8] = b"SS58PRE";

    let mut context = blake2_rfc::blake2b::Blake2b::new(64);
    context.update(PREFIX);
    context.update(data);
    context.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let keypair = Ed25519KeyPair::generate();
        match keypair {
            Ed25519KeyPair(keypair) => {
                let bytes = keypair.to_bytes();
                let secret_key_bytes = &bytes[..SECRET_KEY_LENGTH];
                let public_key_bytes = &bytes[SECRET_KEY_LENGTH..];
                println!("{:?}", keypair.to_bytes());
                println!("{:?}", hex::encode(secret_key_bytes));
                println!("{:?}", hex::encode(public_key_bytes));
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_from_secret_key_bytes() {
        let bytes = [
            203, 83, 75, 248, 221, 21, 169, 1, 238, 68, 44, 174, 81, 11, 36, 111, 94, 148, 36, 125,
            115, 87, 11, 234, 71, 224, 170, 133, 153, 89, 196, 18,
        ];
        let keypair = Ed25519KeyPair::from_secret_key_bytes(&bytes);
        match keypair {
            Ed25519KeyPair(keypair) => {
                let bytes = keypair.to_bytes();
                let secret_key_bytes = &bytes[..SECRET_KEY_LENGTH];
                let public_key_bytes = &bytes[SECRET_KEY_LENGTH..];
                assert_eq!(
                    hex::encode(secret_key_bytes),
                    "cb534bf8dd15a901ee442cae510b246f5e94247d73570bea47e0aa859959c412"
                );
                assert_eq!(
                    hex::encode(public_key_bytes),
                    "b86044c551e40dc1de84aa89c2dcf27657a43e0510f14e9388c1100a76f94e5c"
                );
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_sign() {
        let bytes = [
            203, 83, 75, 248, 221, 21, 169, 1, 238, 68, 44, 174, 81, 11, 36, 111, 94, 148, 36, 125,
            115, 87, 11, 234, 71, 224, 170, 133, 153, 89, 196, 18,
        ];
        let keypair = Ed25519KeyPair::from_secret_key_bytes(&bytes);
        let message = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let signature = keypair.sign(&message);
        let sig_multibase = multibase::encode(multibase::Base::Base58Btc, signature);
        assert_eq!(sig_multibase,"zmqquC4Hb5EK7L7JPQjzABJ8rK8dvpVDgWfN8d6JQ5F96sw91g2mz4m3iPSJ4tQ9jXYE3VmLPvaCBhqQETkEVtbJ");
    }

    #[test]
    fn test_verify_signature() {
        let bytes = [
            203, 83, 75, 248, 221, 21, 169, 1, 238, 68, 44, 174, 81, 11, 36, 111, 94, 148, 36, 125,
            115, 87, 11, 234, 71, 224, 170, 133, 153, 89, 196, 18,
        ];
        let keypair = Ed25519KeyPair::from_secret_key_bytes(&bytes);
        let message = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let sig_multibase = "zmqquC4Hb5EK7L7JPQjzABJ8rK8dvpVDgWfN8d6JQ5F96sw91g2mz4m3iPSJ4tQ9jXYE3VmLPvaCBhqQETkEVtbJ";
        let (_base, sig) = multibase::decode(sig_multibase).unwrap();
        let verify = keypair.verify_signature(&message, &sig);
        assert_eq!(verify, true);
    }
}
