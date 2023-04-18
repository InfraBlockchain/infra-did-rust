use base58::ToBase58;
use bip39::{Language, Mnemonic};
use codec::{Decode, Encode};
use regex::Regex;
use schnorrkel::derive::{ChainCode, Derivation};
use schnorrkel::{ExpansionMode, SecretKey, Signature};
use substrate_bip39::mini_secret_from_entropy;

use lazy_static::lazy_static;

pub struct Sr25519KeyPair(schnorrkel::Keypair);

const SIGNING_CTX: &[u8] = b"substrate";
const JUNCTION_ID_LEN: usize = 32;
const CHAIN_CODE_LENGTH: usize = 32;

impl Sr25519KeyPair {
    pub fn from_bip39_phrase(phrase: &str, password: Option<&str>) -> Option<Sr25519KeyPair> {
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).ok()?;
        let mini_secret_key =
            mini_secret_from_entropy(mnemonic.entropy(), password.unwrap_or("")).ok()?;

        Some(Sr25519KeyPair(
            mini_secret_key.expand_to_keypair(ExpansionMode::Ed25519),
        ))
    }

    // Should match implementation at https://github.com/paritytech/substrate/blob/master/core/primitives/src/crypto.rs#L653-L682
    pub fn from_suri(suri: &str) -> Option<Sr25519KeyPair> {
        lazy_static! {
            static ref RE_SURI: Regex = {
                Regex::new(r"^(?P<phrase>\w+( \w+)*)?(?P<path>(//?[^/]+)*)(///(?P<password>.*))?$")
                    .expect("constructed from known-good static value; qed")
            };
            static ref RE_JUNCTION: Regex =
                Regex::new(r"/(/?[^/]+)").expect("constructed from known-good static value; qed");
        }

        let cap = RE_SURI.captures(suri)?;
        let path = RE_JUNCTION
            .captures_iter(&cap["path"])
            .map(|j| DeriveJunction::from(&j[1]));

        let pair = Self::from_bip39_phrase(
            cap.name("phrase").map(|p| p.as_str())?,
            cap.name("password").map(|p| p.as_str()),
        )?;

        Some(pair.derive(path))
    }

    fn derive(&self, path: impl Iterator<Item = DeriveJunction>) -> Self {
        let init = self.0.secret.clone();
        let result = path.fold(init, |acc, j| match j {
            DeriveJunction::Soft(cc) => acc.derived_key_simple(ChainCode(cc), &[]).0,
            DeriveJunction::Hard(cc) => derive_hard_junction(&acc, cc),
        });

        Sr25519KeyPair(result.to_keypair())
    }

    pub fn ss58_address(&self, prefix: u8) -> String {
        let mut v = vec![prefix];
        v.extend_from_slice(&self.0.public.to_bytes());
        let r = ss58hash(&v);
        v.extend_from_slice(&r.as_bytes()[0..2]);
        v.to_base58()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let context = schnorrkel::signing_context(SIGNING_CTX);
        self.0.sign(context.bytes(message)).to_bytes()
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Option<bool> {
        let context = schnorrkel::signing_context(SIGNING_CTX);

        let signature = Signature::from_bytes(signature).ok()?;

        Some(self.0.verify(context.bytes(&message), &signature).is_ok())
    }
}

fn derive_hard_junction(secret: &SecretKey, cc: [u8; CHAIN_CODE_LENGTH]) -> SecretKey {
    secret
        .hard_derive_mini_secret_key(Some(ChainCode(cc)), b"")
        .0
        .expand(ExpansionMode::Ed25519)
}

/// A since derivation junction description. It is the single parameter used when creating
/// a new secret key from an existing secret key and, in the case of `SoftRaw` and `SoftIndex`
/// a new public key from an existing public key.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Encode, Decode)]
enum DeriveJunction {
    /// Soft (vanilla) derivation. Public keys have a correspondent derivation.
    Soft([u8; JUNCTION_ID_LEN]),
    /// Hard ("hardened") derivation. Public keys do not have a correspondent derivation.
    Hard([u8; JUNCTION_ID_LEN]),
}

impl DeriveJunction {
    /// Consume self to return a hard derive junction with the same chain code.
    fn harden(self) -> Self {
        DeriveJunction::Hard(self.unwrap_inner())
    }

    /// Create a new soft (vanilla) DeriveJunction from a given, encodable, value.
    ///
    /// If you need a hard junction, use `hard()`.
    fn soft<T: Encode>(index: T) -> Self {
        let mut cc: [u8; JUNCTION_ID_LEN] = Default::default();
        index.using_encoded(|data| {
            if data.len() > JUNCTION_ID_LEN {
                let hash_result = blake2_rfc::blake2b::blake2b(JUNCTION_ID_LEN, &[], data);
                let hash = hash_result.as_bytes();
                cc.copy_from_slice(hash);
            } else {
                cc[0..data.len()].copy_from_slice(data);
            }
        });
        DeriveJunction::Soft(cc)
    }

    /// Consume self to return the chain code.
    fn unwrap_inner(self) -> [u8; JUNCTION_ID_LEN] {
        match self {
            DeriveJunction::Hard(c) | DeriveJunction::Soft(c) => c,
        }
    }
}

impl<T: AsRef<str>> From<T> for DeriveJunction {
    fn from(j: T) -> DeriveJunction {
        let j = j.as_ref();
        let (code, hard) = if j.starts_with("/") {
            (&j[1..], true)
        } else {
            (j, false)
        };

        let res = if let Ok(n) = str::parse::<u64>(code) {
            // number
            DeriveJunction::soft(n)
        } else {
            // something else
            DeriveJunction::soft(code)
        };

        if hard {
            res.harden()
        } else {
            res
        }
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
    use schnorrkel::SECRET_KEY_LENGTH;

    use super::*;

    #[test]
    fn test_from_bip39_phrase() {
        let keypair = Sr25519KeyPair::from_bip39_phrase(
            "true crowd stereo border country ocean mountain sadness term stumble media glory",
            Some(""),
        )
        .unwrap();
        match keypair {
            Sr25519KeyPair(keypair) => {
                let keypair_bytes = keypair.to_bytes();
                let secret_key_bytes = &keypair_bytes[..SECRET_KEY_LENGTH];
                let publuc_key_bytes = &keypair_bytes[SECRET_KEY_LENGTH..];
                assert_eq!(hex::encode(secret_key_bytes),"b3370307d69f13cece7c28b2fa6380bcd56e9f32c9daa5a7be545efb65bc370dbab0ac540259f83925afca9192fa73f99f3ec9ca1c8da3297b0e05a87fee3df3");
                assert_eq!(
                    hex::encode(publuc_key_bytes),
                    "f02283ff600d00613244e1e43dc88d56fec666223de7ebeb3f32e93a375fe12b"
                );
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_from_suri() {
        let keypair = Sr25519KeyPair::from_suri(
            "true crowd stereo border country ocean mountain sadness term stumble media glory",
        )
        .unwrap();
        match keypair {
            Sr25519KeyPair(keypair) => {
                let keypair_bytes = keypair.to_bytes();
                let secret_key_bytes = &keypair_bytes[..SECRET_KEY_LENGTH];
                let publuc_key_bytes = &keypair_bytes[SECRET_KEY_LENGTH..];
                assert_eq!(hex::encode(secret_key_bytes),"b3370307d69f13cece7c28b2fa6380bcd56e9f32c9daa5a7be545efb65bc370dbab0ac540259f83925afca9192fa73f99f3ec9ca1c8da3297b0e05a87fee3df3");
                assert_eq!(
                    hex::encode(publuc_key_bytes),
                    "f02283ff600d00613244e1e43dc88d56fec666223de7ebeb3f32e93a375fe12b"
                );
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn test_ss58_address() {
        let keypair = Sr25519KeyPair::from_suri(
            "true crowd stereo border country ocean mountain sadness term stumble media glory",
        )
        .unwrap();
        let address = keypair.ss58_address(42);
        assert_eq!(address, "5HVZbuy7bpM8NX7VXTyxoL5dvk5W3496vkknoWtVhF7cRjc3");
    }

    #[test]
    fn test_sign() {
        let keypair = Sr25519KeyPair::from_suri(
            "true crowd stereo border country ocean mountain sadness term stumble media glory",
        )
        .unwrap();
        let message = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let signature = keypair.sign(&message);
        // sr25519 signature is non-deterministic
        assert_eq!(hex::encode(signature).len(), 128);
    }

    #[test]
    fn test_verify_signature() {
        let keypair = Sr25519KeyPair::from_suri(
            "true crowd stereo border country ocean mountain sadness term stumble media glory",
        )
        .unwrap();
        let message = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let signature = [
            80, 147, 218, 23, 52, 24, 12, 20, 87, 87, 240, 184, 36, 197, 125, 76, 121, 152, 133,
            133, 226, 196, 178, 32, 112, 254, 10, 160, 116, 123, 149, 57, 11, 223, 29, 28, 192, 78,
            190, 6, 248, 99, 45, 96, 43, 87, 164, 205, 213, 177, 62, 199, 240, 195, 50, 21, 209,
            155, 206, 38, 7, 23, 245, 143,
        ];
        let verify = keypair.verify_signature(&message, &signature).unwrap();
        assert_eq!(verify, true);
    }
}
