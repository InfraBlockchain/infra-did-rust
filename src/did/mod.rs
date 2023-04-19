use bip39::{Language, Mnemonic, MnemonicType, Seed};
use ed25519_dalek::{PublicKey, SecretKey};
use schnorrkel::{ExpansionMode, SECRET_KEY_LENGTH};
use serde_json::json;
use substrate_bip39::mini_secret_from_entropy;

use crate::crypto::sr25519::Sr25519KeyPair;

pub fn random_phrase(words_number: u32) -> String {
    let mnemonic_type = match MnemonicType::for_word_count(words_number as usize) {
        Ok(t) => t,
        Err(_e) => MnemonicType::Words24,
    };
    let mnemonic = Mnemonic::new(mnemonic_type, Language::English);

    mnemonic.into_phrase()
}

pub fn substrate_address(suri: String, prefix: u8) -> String {
    let keypair_option = Sr25519KeyPair::from_suri(suri.as_str());
    let keypair = match keypair_option {
        Some(c) => c,
        _ => return "".to_string(),
    };

    let rust_string = keypair.ss58_address(prefix);
    rust_string
}

pub fn generate_ss58_did(network_id: String) -> String {
    let mnemonic_type = MnemonicType::for_word_count(12).unwrap();
    let mnemonic = Mnemonic::new(mnemonic_type, Language::English);

    let keypair_option = Sr25519KeyPair::from_suri(mnemonic.clone().into_phrase().as_str());

    let keypair = match keypair_option {
        Some(c) => c,
        _ => return "".to_string(),
    };

    let address = keypair.ss58_address(42);
    let did = format!("did:infra:{}:{}", network_id, address.clone());

    let mini_secret_key = mini_secret_from_entropy(mnemonic.entropy(), "").unwrap();

    let secret_key = mini_secret_key;
    let public_key = secret_key.expand_to_public(ExpansionMode::Ed25519);

    let result = serde_json::to_string(&json!({
        "mnemonic": mnemonic.into_phrase(),
        "private_key": hex::encode(secret_key.to_bytes()),
        "public_key": hex::encode(public_key.to_bytes()),
        "address": address.clone(),
        "did": did
    }));

    result.unwrap()
}

pub fn generate_ss58_did_from_phrase(suri: String, network_id: String) -> String {
    let keypair_option = Sr25519KeyPair::from_suri(suri.as_str());

    let keypair = match keypair_option {
        Some(c) => c,
        _ => return "".to_string(),
    };

    let address = keypair.ss58_address(42);
    let did = format!("did:infra:{}:{}", network_id, address.clone());

    let mnemonic = Mnemonic::from_phrase(&suri, Language::English).unwrap();
    let mini_secret_key = mini_secret_from_entropy(mnemonic.entropy(), "").unwrap();

    let secret_key = mini_secret_key;
    let public_key = secret_key.expand_to_public(ExpansionMode::Ed25519);

    let result = serde_json::to_string(&json!({
        "private_key": hex::encode(secret_key.to_bytes()),
        "public_key": hex::encode(public_key.to_bytes()),
        "address": address.clone(),
        "did": did
    }));

    result.unwrap()
}

pub fn did_to_hex_public_key(did: String) -> String {
    let splited_did: Vec<&str> = did.split(":").collect();
    let address = splited_did[3];

    let decoded_address = bs58::decode(address).into_vec().unwrap();

    let public_key: schnorrkel::PublicKey =
        schnorrkel::PublicKey::from_bytes(&decoded_address[1..33]).unwrap();

    hex::encode(public_key.to_bytes())
}

pub fn ss58_address_to_did(address: String, network_id: String) -> String {
    let did = format!("did:infra:{}:{}", network_id, address);
    did
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testa() {
        println!(
            "{:?}",
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        );
    }

    #[test]
    fn test_generate_random_phrase() {
        println!("{:?}", random_phrase(12));
    }

    #[test]
    fn test_generate_ss58_did() {
        println!("{:?}", generate_ss58_did("01".to_string()));
    }

    #[test]
    fn test_generate_ss58_did_from_phrase() {
        println!(
            "{:?}",
            generate_ss58_did_from_phrase(
                "caution juice atom organ advance problem want pledge someone senior holiday very"
                    .to_string(),
                "01".to_string()
            )
        );
    }

    #[test]
    fn test_did_to_hex_public_key() {
        assert_eq!(
            did_to_hex_public_key(
                "did:infra:01:5Gv8YYFu8H1btvmrJy9FjjAWfb99wrhV3uhPFoNEr918utyR".to_string()
            ),
            "d6a3105d6768e956e9e5d41050ac29843f98561410d3a47f9dd5b3b227ab8746".to_string()
        );
    }

    #[test]
    fn test_ss58_address_to_did() {
        assert_eq!(
            ss58_address_to_did(
                "5H6PhTQ1ukXBE1pqYVt2BMLjiKD9pqVsoppp2g8eM4EENAfL".to_string(),
                "01".to_string()
            ),
            "did:infra:01:5H6PhTQ1ukXBE1pqYVt2BMLjiKD9pqVsoppp2g8eM4EENAfL".to_string()
        );
    }
}
