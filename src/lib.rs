use bip39::{Language, Mnemonic, MnemonicType, Seed};
use schnorrkel::ExpansionMode;
use serde_json::json;
use sr25519::KeyPair;
use substrate_bip39::mini_secret_from_entropy;

mod sr25519;

pub fn _random_phrase(words_number: u32) -> String {
    let mnemonic_type = match MnemonicType::for_word_count(words_number as usize) {
        Ok(t) => t,
        Err(_e) => MnemonicType::Words24,
    };
    let mnemonic = Mnemonic::new(mnemonic_type, Language::English);

    mnemonic.into_phrase()
}

pub fn _substrate_address(suri: String, prefix: u8) -> String {
    let keypair_option = KeyPair::from_suri(suri.as_str());
    let keypair = match keypair_option {
        Some(c) => c,
        _ => return "".to_string(),
    };

    let rust_string = keypair.ss58_address(prefix);
    rust_string
}

pub fn _generate_ss58_did(network_id: String) -> String {
    let mnemonic_type = MnemonicType::for_word_count(12).unwrap();
    let mnemonic = Mnemonic::new(mnemonic_type, Language::English);

    let keypair_option = KeyPair::from_suri(mnemonic.clone().into_phrase().as_str());

    let keypair = match keypair_option {
        Some(c) => c,
        _ => return "".to_string(),
    };

    let seed = Seed::new(&mnemonic, "");

    let address = keypair.ss58_address(42);
    let did = format!("did:infra:{}:{}", network_id, address.clone());

    let mini_secret_key = mini_secret_from_entropy(mnemonic.entropy(), "").unwrap();

    let secret_key: schnorrkel::SecretKey = mini_secret_key.expand(ExpansionMode::Ed25519);
    let public_key: schnorrkel::PublicKey = secret_key.to_public();

    let result = serde_json::to_string(&json!({
        "mnemonic": mnemonic.into_phrase(),
        "seed": hex::encode(seed.clone()),
        "private_key": hex::encode(secret_key.to_bytes()),
        "public_key": hex::encode(public_key.to_bytes()),
        "address": address.clone(),
        "did": did
    }));

    result.unwrap()
}

#[no_mangle]
pub fn _did_to_hex_public_key(did: String) -> String {
    let splited_did: Vec<&str> = did.split(":").collect();
    let address = splited_did[3];

    let decoded_address = bs58::decode(address).into_vec().unwrap();

    let public_key: schnorrkel::PublicKey =
        schnorrkel::PublicKey::from_bytes(&decoded_address[1..33]).unwrap();

    hex::encode(public_key.to_bytes())
}

#[no_mangle]
pub fn _ss58_address_to_did(address: String, network_id: String) -> String {
    let did = format!("did:infra:{}:{}", network_id, address);
    did
}

#[test]
fn test_generate_ss58_did() {
    println!("{:?}", _generate_ss58_did("01".to_string()));
}

#[test]
fn test_did_to_hex_public_key() {
    assert_eq!(
        _did_to_hex_public_key(
            "did:infra:01:5H6PhTQ1ukXBE1pqYVt2BMLjiKD9pqVsoppp2g8eM4EENAfL".to_string()
        ),
        "de7687abb0442514b3f765e17f6cde78227e3b5afa45627f12d805fb5c5e473a".to_string()
    );
}

#[test]
fn test_ss58_address_to_did() {
    assert_eq!(
        _ss58_address_to_did(
            "5H6PhTQ1ukXBE1pqYVt2BMLjiKD9pqVsoppp2g8eM4EENAfL".to_string(),
            "01".to_string()
        ),
        "did:infra:01:5H6PhTQ1ukXBE1pqYVt2BMLjiKD9pqVsoppp2g8eM4EENAfL".to_string()
    );
}
