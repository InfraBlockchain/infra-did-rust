# infra-did-rust

**This Library is rust version of ss58 based did in infra-did-js**

-   Infra DID Method Spec

    -   https://github.com/InfraBlockchain/infra-did-method-specs/blob/main/docs/Infra-DID-method-spec.md

-   Infra DID Registry Smart Contract on InfraBlockchain

    -   https://github.com/InfraBlockchain/infra-did-registry

-   Infra DID Resolver (DIF javascript universal resolver compatible)
    -   https://github.com/InfraBlockchain/infra-did-resolver

Feature provided by infra-did-rust Library :

-   Infra DID Creation (SS58)
-   Resolve Infra DID (SS58)
-   JSON-LD VC/VP creation/verification

## Installation

-   **Using [crates](https://crates.io/)**:

```sh
cargo add infra-did
```

### Infra DID Creation

currently ed25519 curve is supported

```rust
    println!("{:?}", generate_ss58_did("01".to_string(), AddressType::Ed25519));
  /*
    {
        "address":"5FEWTgcxvefibCpoy7rfPx7WKimuWAuRx7JZmhwRTvQosZse","did":"did:infra:01:5FEWTgcxvefibCpoy7rfPx7WKimuWAuRx7JZmhwRTvQosZse",
        "mnemonic":"second lucky rifle size spray advance approve view melody carpet offer thumb","private_key":"0177ced8efef49f17fec276d56de1b2037fbcc6348693d22436633043247a942","public_key":"8c2eca839176ba7b2ee50aa8aa1dc406abb89a4ebe2d90fcda489fee29795c94"
    }
   */
```

### Issuing and Verifying W3C Verifiable Credential (VC), Verifiable Presentation (VP)

#### DID Resolver

```rust
    let resolver = InfraDIDResolver::default();
    let (_, doc, _) = resolver
        .resolve(
            "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW",
            &ResolutionInputMetadata::default(),
        )
        .await;
    println!("{:?}", serde_json::to_string_pretty(&doc).unwrap());
    /*
        {
          "@context": "https://www.w3.org/ns/did/v1",
          "id": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW",
          "verificationMethod": [
            {
              "id": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW#keys-1",
              "type": "Ed25519VerificationKey2018",
              "controller": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW",
              "publicKeyBase58": "F9JHKboDqg3tK9wnrt8z8xwZRnoZCJAHTdxXVuUMW8z2"
            },
            {
              "id": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW#keys-2",
              "type": "Ed25519VerificationKey2020",
              "controller": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW",
              "publicKeyMultibase": "z6MktbZKur3fBDYMRenVYT6pz4VZFN5QcBQe9esTLBSNRMmQ"
            }
          ],
          "authentication": [
            "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW#keys-1",
            "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW#keys-2"
          ],
          "assertionMethod": [
            "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW#keys-1",
            "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW#keys-2"
          ]
        }
    */
```

#### Create and Verify Verifiable Credential JSON-LD

```rust
    let did = "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW".to_string();
    let hex_secret_key =
        "8006aaa5985f1d72e916167bdcbc663232cef5823209b1246728f73137888170".to_string();
    let vc_str = r###"{
        "@context": [
            "https://www.w3.org/2018/credentials/v1"
        ],
        "id": "did:infra:space:5FDseiC76zPek2YYkuyenu4ZgxZ7PUWXt9d19HNB5CaQXt5U",
        "type": [
            "VerifiableCredential"
        ],
        "credentialSubject": [
            {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        ],
        "issuanceDate": "2023-04-24T06:08:03.039Z",
        "issuer": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW"
    }"###;

    let vc = issue_credential(did, hex_secret_key, vc_str.to_string()).await;
    let verify = verify_credential(vc.to_string()).await.unwrap();
    assert_eq!(verify, "true".to_string());
```

Verified Credential Result

```json
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1"
      ],
      "id": "did:infra:space:5FDseiC76zPek2YYkuyenu4ZgxZ7PUWXt9d19HNB5CaQXt5U",
      "type": [
        "VerifiableCredential"
      ],
      "credentialSubject": [
        {
          "id": "did:example:d23dd687a7dc6787646f2eb98d0"
        }
      ],
      "issuer": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW",
      "issuanceDate": "2023-04-24T06:08:03.039Z",
      "proof": {
        "@context": [
          "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "type": "Ed25519Signature2020",
        "proofPurpose": "assertionMethod",
        "proofValue": "z5LPkbsnBbYTAJJ3fcwkEBtbfkT2wnLhLNmcSwj2e8FSYfMrrWoFey6958gm7G93UfTu6qkLkD1nwgzbzSihbu3jw",
        "verificationMethod": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW#keys-2",
        "created": "2023-04-30T23:53:20.028Z"
      }
    }
```

#### Create and Verify Verifiable Presentation JSON-LD

```rust        
  let did = "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW".to_string();
  let hex_secret_key = "8006aaa5985f1d72e916167bdcbc663232cef5823209b1246728f73137888170".to_string();
  let vc_str = r###"{
      "@context": [
          "https://www.w3.org/2018/credentials/v1"
      ],
      "id": "did:infra:space:5FDseiC76zPek2YYkuyenu4ZgxZ7PUWXt9d19HNB5CaQXt5U",
      "type": [
          "VerifiableCredential"
      ],
      "credentialSubject": [
          {
              "id": "did:example:d23dd687a7dc6787646f2eb98d0"
          }
      ],
      "issuer": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW",
      "issuanceDate": "2023-04-24T06:08:03.039Z",
      "proof": {
          "@context": [
              "https://w3id.org/security/suites/ed25519-2020/v1"
          ],
          "type": "Ed25519Signature2020",
          "proofPurpose": "assertionMethod",
          "proofValue": "z3gFJvCvNYTVQJ7R7tXzbmAyZ62g3ZymbzwTrWJhgwatJouope5GnQmz7NW2zAVVYbor5KUW8TUa1V5KADPp8kBog",
          "verificationMethod": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW#keys-2",
          "created": "2023-04-25T23:52:13.770Z"
      }
  }"###;

  let vp = issue_presentation(did, hex_secret_key, vc_str.to_string()).await;
  let verify: String = verify_presentation(vp.to_string()).await.unwrap();
  assert_eq!(verify, "true".to_string());
```

Verified Presentation Result

```json
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1"
      ],
      "id": "did:infra:01:5D7nQ3WTPtJx79ywCbLum7fyVt1DKcg32jB6SdABhhwpzT9a",
      "type": "VerifiablePresentation",
      "verifiableCredential": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1"
        ],
        "id": "did:infra:space:5FDseiC76zPek2YYkuyenu4ZgxZ7PUWXt9d19HNB5CaQXt5U",
        "type": [
          "VerifiableCredential"
        ],
        "credentialSubject": [
          {
            "id": "did:example:d23dd687a7dc6787646f2eb98d0"
          }
        ],
        "issuer": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW",
        "issuanceDate": "2023-04-24T06:08:03.039Z",
        "proof": {
          "@context": [
            "https://w3id.org/security/suites/ed25519-2020/v1"
          ],
          "type": "Ed25519Signature2020",
          "proofPurpose": "assertionMethod",
          "proofValue": "z3gFJvCvNYTVQJ7R7tXzbmAyZ62g3ZymbzwTrWJhgwatJouope5GnQmz7NW2zAVVYbor5KUW8TUa1V5KADPp8kBog",
          "verificationMethod": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW#keys-2",
          "created": "2023-04-25T23:52:13.770Z"
        }
      },
      "proof": {
        "@context": [
          "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "type": "Ed25519Signature2020",
        "proofPurpose": "assertionMethod",
        "proofValue": "zWPTW2TC7WcEUk1F25saJxHKKt2HjsdSW3GEk12d2mJbUN2dJntEBng9N1RmZz6XuHqNuh7Dq1d4DTpyZ1GEokRq",
        "verificationMethod": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW#keys-2",
        "created": "2023-05-01T00:03:59.511Z"
      },
      "holder": "did:infra:space:5GpEYnXBoLgvzyWe4Defitp5UV25xZUiUCJM2xNgkDXkM4NW"
    }
```