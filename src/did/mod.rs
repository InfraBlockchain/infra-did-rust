use bip39::{Language, Mnemonic, MnemonicType};
use schnorrkel::ExpansionMode;
use serde_json::json;
use substrate_bip39::mini_secret_from_entropy;

use crate::crypto::{ed25519::Ed25519KeyPair, sr25519::Sr25519KeyPair};

pub enum AddressType {
    Ed25519,
    Sr25519,
}
pub fn random_phrase(words_number: u32) -> String {
    let mnemonic_type = match MnemonicType::for_word_count(words_number as usize) {
        Ok(t) => t,
        Err(_e) => MnemonicType::Words24,
    };
    let mnemonic = Mnemonic::new(mnemonic_type, Language::English);

    mnemonic.into_phrase()
}

pub fn generate_ss58_did(network_id: String, address_type: AddressType) -> String {
    let mnemonic_type = MnemonicType::for_word_count(12).unwrap();
    let mnemonic = Mnemonic::new(mnemonic_type, Language::English);

    match address_type {
        AddressType::Ed25519 => {
            let keypair: Ed25519KeyPair = Ed25519KeyPair::from_bip39_phrase(
                mnemonic.clone().into_phrase().as_str(),
                Some(""),
            );

            let address = keypair.ss58_address(42);
            let did = format!("did:infra:{}:{}", network_id, address.clone());

            let result = serde_json::to_string(&json!({
                "mnemonic": mnemonic.into_phrase(),
                "private_key": hex::encode(keypair.to_secret_key_bytes()),
                "public_key": hex::encode(keypair.to_public_key_bytes()),
                "address": address.clone(),
                "did": did
            }));
            result.unwrap()
        }
        AddressType::Sr25519 => {
            let keypair_option: Option<Sr25519KeyPair> =
                Sr25519KeyPair::from_suri(mnemonic.clone().into_phrase().as_str());

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
    }
}

pub fn generate_ss58_did_from_phrase(
    suri: String,
    network_id: String,
    address_type: AddressType,
) -> String {
    match address_type {
        AddressType::Ed25519 => {
            let keypair: Ed25519KeyPair =
                Ed25519KeyPair::from_bip39_phrase(suri.clone().as_str(), Some(""));

            let address = keypair.ss58_address(42);
            let did = format!("did:infra:{}:{}", network_id, address.clone());

            let result = serde_json::to_string(&json!({
                "mnemonic": suri,
                "private_key": hex::encode(keypair.to_secret_key_bytes()),
                "public_key": hex::encode(keypair.to_public_key_bytes()),
                "address": address.clone(),
                "did": did
            }));
            result.unwrap()
        }
        AddressType::Sr25519 => {
            let keypair_option: Option<Sr25519KeyPair> =
                Sr25519KeyPair::from_suri(suri.clone().as_str());

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
                "mnemonic": suri,
                "private_key": hex::encode(secret_key.to_bytes()),
                "public_key": hex::encode(public_key.to_bytes()),
                "address": address.clone(),
                "did": did
            }));
            result.unwrap()
        }
    }
}

pub fn did_to_hex_public_key(did: String, address_type: AddressType) -> String {
    let splited_did: Vec<&str> = did.split(":").collect();
    let address = splited_did[3];

    let decoded_address = bs58::decode(address).into_vec().unwrap();

    let public_key_bytes: [u8; 32] = match address_type {
        AddressType::Ed25519 => {
            let public_key: ed25519_dalek::PublicKey =
                ed25519_dalek::PublicKey::from_bytes(&decoded_address[1..33]).unwrap();
            public_key.to_bytes()
        }
        AddressType::Sr25519 => {
            let public_key: schnorrkel::PublicKey =
                schnorrkel::PublicKey::from_bytes(&decoded_address[1..33]).unwrap();
            public_key.to_bytes()
        }
    };

    hex::encode(public_key_bytes)
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
            hex::decode("8006aaa5985f1d72e916167bdcbc663232cef5823209b1246728f73137888170")
        );
    }

    #[test]
    fn test_generate_random_phrase() {
        println!("{:?}", random_phrase(12));
    }

    #[test]
    fn test_generate_ss58_did() {
        println!(
            "{:?}",
            generate_ss58_did("01".to_string(), AddressType::Ed25519)
        );
        println!(
            "{:?}",
            generate_ss58_did("01".to_string(), AddressType::Sr25519)
        );
    }

    #[test]
    fn test_generate_ss58_did_from_phrase() {
        assert_eq!(
            r###"{"address":"5GM7RtekqU8cGiS4MKQ7tufoH4Q1itzmoFpVcvcPfjksyPrw","did":"did:infra:01:5GM7RtekqU8cGiS4MKQ7tufoH4Q1itzmoFpVcvcPfjksyPrw","mnemonic":"caution juice atom organ advance problem want pledge someone senior holiday very","private_key":"c8fa03532fb22ee1f7f6908b9c02b4e72483f0dbd66e4cd456b8f34c6230b849","public_key":"bd7436a22571207d018ffe83f5dc77d0750b7777f1eb169053d40201d6c68d53"}"###,
            generate_ss58_did_from_phrase(
                "caution juice atom organ advance problem want pledge someone senior holiday very"
                    .to_string(),
                "01".to_string(),
                AddressType::Ed25519
            )
        );

        assert_eq!(
            r###"{"address":"5Gv8YYFu8H1btvmrJy9FjjAWfb99wrhV3uhPFoNEr918utyR","did":"did:infra:01:5Gv8YYFu8H1btvmrJy9FjjAWfb99wrhV3uhPFoNEr918utyR","mnemonic":"caution juice atom organ advance problem want pledge someone senior holiday very","private_key":"c8fa03532fb22ee1f7f6908b9c02b4e72483f0dbd66e4cd456b8f34c6230b849","public_key":"d6a3105d6768e956e9e5d41050ac29843f98561410d3a47f9dd5b3b227ab8746"}"###,
            generate_ss58_did_from_phrase(
                "caution juice atom organ advance problem want pledge someone senior holiday very"
                    .to_string(),
                "01".to_string(),
                AddressType::Sr25519
            )
        );
    }

    #[test]
    fn test_did_to_hex_public_key() {
        assert_eq!(
            did_to_hex_public_key(
                "did:infra:01:5GM7RtekqU8cGiS4MKQ7tufoH4Q1itzmoFpVcvcPfjksyPrw".to_string(),
                AddressType::Ed25519
            ),
            "bd7436a22571207d018ffe83f5dc77d0750b7777f1eb169053d40201d6c68d53".to_string()
        );

        assert_eq!(
            did_to_hex_public_key(
                "did:infra:01:5Gv8YYFu8H1btvmrJy9FjjAWfb99wrhV3uhPFoNEr918utyR".to_string(),
                AddressType::Sr25519
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
