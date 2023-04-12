use bip39::{Language, Mnemonic, MnemonicType, Seed};
use schnorrkel::ExpansionMode;
use serde_json::json;
use sr25519::KeyPair;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use substrate_bip39::mini_secret_from_entropy;

mod sr25519;

fn get_str(rust_ptr: *const c_char) -> String {
    let c_str = unsafe { CStr::from_ptr(rust_ptr) };
    let result_string = match c_str.to_str() {
        Err(_) => "input string error",
        Ok(string) => string,
    };
    return String::from(result_string);
}

fn get_ptr(rust_string: &str) -> *mut c_char {
    CString::new(rust_string).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn random_phrase(words_number: u32) -> *mut c_char {
    let mnemonic_type = match MnemonicType::for_word_count(words_number as usize) {
        Ok(t) => t,
        Err(_e) => MnemonicType::Words24,
    };
    let mnemonic = Mnemonic::new(mnemonic_type, Language::English);

    get_ptr(&mnemonic.into_phrase())
}

#[no_mangle]
pub extern "C" fn substrate_address(suri: *const c_char, prefix: u8) -> *mut c_char {
    let keypair_option = KeyPair::from_suri(&get_str(suri));
    let keypair = match keypair_option {
        Some(c) => c,
        _ => return get_ptr(""),
    };

    let rust_string = keypair.ss58_address(prefix);
    get_ptr(&rust_string)
}

#[no_mangle]
pub extern "C" fn generate_ss58_did(network_id: *const c_char) -> *mut c_char {
    let mnemonic_type = MnemonicType::for_word_count(12).unwrap();
    let mnemonic = Mnemonic::new(mnemonic_type, Language::English);

    let keypair_option = KeyPair::from_suri(mnemonic.clone().into_phrase().as_str());

    let keypair = match keypair_option {
        Some(c) => c,
        _ => return get_ptr(""),
    };

    let seed = Seed::new(&mnemonic, "");

    let network_id_string = get_str(network_id);
    let address = keypair.ss58_address(42);
    let did = format!("did:infra:{}:{}", network_id_string, address.clone());

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

    get_ptr(&result.unwrap())
}

#[no_mangle]
pub extern "C" fn did_to_hex_public_key(did: *mut c_char) -> *mut c_char {
    let did_string = get_str(did);
    let splited_did: Vec<&str> = did_string.split(":").collect();
    let address = splited_did[3];

    let decoded_address = bs58::decode(address).into_vec().unwrap();

    let public_key: schnorrkel::PublicKey =
        schnorrkel::PublicKey::from_bytes(&decoded_address[1..33]).unwrap();

    get_ptr(&hex::encode(public_key.to_bytes()))
}

#[no_mangle]
pub extern "C" fn ss58_address_to_did(
    address: *mut c_char,
    network_id: *mut c_char,
) -> *mut c_char {
    let address_string = get_str(address);
    let network_id_string = get_str(network_id);

    let did = format!("did:infra:{}:{}", network_id_string, address_string);
    get_ptr(&did)
}

#[no_mangle]
pub extern "C" fn rust_cstr_free(s: *mut c_char) {
    unsafe {
        if s.is_null() {
            return;
        }
        CString::from_raw(s)
    };
}

#[test]
fn test_generate_ss58_did() {
    println!("{:?}", generate_ss58_did(get_ptr("01")));
}

#[test]
fn test_did_to_hex_public_key() {
    assert_eq!(
        get_str(did_to_hex_public_key(get_ptr(
            "did:infra:01:5H6PhTQ1ukXBE1pqYVt2BMLjiKD9pqVsoppp2g8eM4EENAfL"
        ))),
        "de7687abb0442514b3f765e17f6cde78227e3b5afa45627f12d805fb5c5e473a"
    );
}

#[test]
fn test_ss58_address_to_did() {
    assert_eq!(
        get_str(ss58_address_to_did(
            get_ptr("5H6PhTQ1ukXBE1pqYVt2BMLjiKD9pqVsoppp2g8eM4EENAfL"),
            get_ptr("01")
        )),
        "did:infra:01:5H6PhTQ1ukXBE1pqYVt2BMLjiKD9pqVsoppp2g8eM4EENAfL"
    );
}
