use base58::ToBase58;
use bip39::{Language, Mnemonic};
use ed25519_dalek::{
    Keypair, PublicKey, SecretKey, Signature, Signer, Verifier, KEYPAIR_LENGTH, SECRET_KEY_LENGTH,
};
use rand::rngs::OsRng;
use substrate_bip39::mini_secret_from_entropy;

pub struct Ed25519KeyPair(ed25519_dalek::Keypair);

impl Ed25519KeyPair {
    pub fn generate() -> Ed25519KeyPair {
        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        Ed25519KeyPair(keypair)
    }

    pub fn from_bip39_phrase(phrase: &str, password: Option<&str>) -> Ed25519KeyPair {
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let mini_secret_key =
            mini_secret_from_entropy(mnemonic.entropy(), password.unwrap_or("")).unwrap();

        let secret_key: SecretKey = SecretKey::from_bytes(mini_secret_key.as_bytes()).unwrap();
        let public_key: PublicKey = PublicKey::from(&secret_key).into();

        let secret = secret_key.to_bytes();
        let public = public_key.to_bytes();

        let mut keypair_bytes: [u8; KEYPAIR_LENGTH] = [0u8; KEYPAIR_LENGTH];

        keypair_bytes[..SECRET_KEY_LENGTH].copy_from_slice(&secret);
        keypair_bytes[SECRET_KEY_LENGTH..].copy_from_slice(&public);

        let keypair = ed25519_dalek::Keypair::from_bytes(&keypair_bytes).ok();
        Ed25519KeyPair(keypair.unwrap())
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

    pub fn from_public_key_bytes(bytes: &[u8]) -> Ed25519KeyPair {
        let public_key: PublicKey = PublicKey::from_bytes(bytes).unwrap();

        let public = public_key.to_bytes();

        let mut keypair_bytes: [u8; KEYPAIR_LENGTH] = [0u8; KEYPAIR_LENGTH];

        keypair_bytes[SECRET_KEY_LENGTH..].copy_from_slice(&public);

        let keypair = ed25519_dalek::Keypair::from_bytes(&keypair_bytes).ok();
        Ed25519KeyPair(keypair.unwrap())
    }

    pub fn to_public_key_bytes(&self) -> [u8; 32] {
        self.0.public.to_bytes()
    }

    pub fn to_secret_key_bytes(&self) -> [u8; 32] {
        self.0.secret.to_bytes()
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
        }
    }

    #[test]
    fn test_from_bip39_phrase() {
        let keypair = Ed25519KeyPair::from_bip39_phrase(
            "caution juice atom organ advance problem want pledge someone senior holiday very",
            Some(""),
        );
        match keypair {
            Ed25519KeyPair(keypair) => {
                let keypair_bytes = keypair.to_bytes();
                let secret_key_bytes = &keypair_bytes[..SECRET_KEY_LENGTH];
                let publuc_key_bytes = &keypair_bytes[SECRET_KEY_LENGTH..];
                assert_eq!(
                    hex::encode(secret_key_bytes),
                    "c8fa03532fb22ee1f7f6908b9c02b4e72483f0dbd66e4cd456b8f34c6230b849"
                );
                assert_eq!(
                    hex::encode(publuc_key_bytes),
                    "bd7436a22571207d018ffe83f5dc77d0750b7777f1eb169053d40201d6c68d53"
                );
            }
        }
    }

    #[test]
    fn test_from_secret_key_bytes() {
        // https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
        let bytes = [
            157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73, 197,
            105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
        ];
        let keypair = Ed25519KeyPair::from_secret_key_bytes(&bytes);
        match keypair {
            Ed25519KeyPair(keypair) => {
                let bytes = keypair.to_bytes();
                let secret_key_bytes = &bytes[..SECRET_KEY_LENGTH];
                let public_key_bytes = &bytes[SECRET_KEY_LENGTH..];
                assert_eq!(
                    hex::encode(secret_key_bytes),
                    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
                );
                assert_eq!(
                    hex::encode(public_key_bytes),
                    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                );
            }
        }
    }

    #[test]
    fn test_sign() {
        let bytes = [
            157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73, 197,
            105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
        ];
        let keypair = Ed25519KeyPair::from_secret_key_bytes(&bytes);
        println!("{:?}", keypair.to_secret_key_bytes());
        println!("{:?}", keypair.to_public_key_bytes());
        let message = [];
        let signature = keypair.sign(&message);
        let sig_multibase = multibase::encode(multibase::Base::Base58Btc, signature);
        assert_eq!(sig_multibase,"z5awYiUvGiDFA33EJjj4TXJG44a5afJc8QjWRpGgQiu6b23jCr7yndW2fmp9ujwqJVe32J456wV3VF78Asb1obnTc");
    }

    #[test]
    fn test_verify_signature() {
        let bytes = [
            215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114,
            243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
        ];
        let keypair = Ed25519KeyPair::from_public_key_bytes(&bytes);
        let message = [];
        let sig_multibase = "z5awYiUvGiDFA33EJjj4TXJG44a5afJc8QjWRpGgQiu6b23jCr7yndW2fmp9ujwqJVe32J456wV3VF78Asb1obnTc";
        let (_base, sig) = multibase::decode(sig_multibase).unwrap();
        let verify = keypair.verify_signature(&message, &sig);
        assert_eq!(verify, true);
    }
}
