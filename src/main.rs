use anyhow::anyhow;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::hash::{Blake2b256, HashFunction, Sha256, Sha3_256};
use fastcrypto::secp256r1::{Secp256r1PublicKey, Secp256r1Signature};
use fastcrypto::traits::{ToFromBytes, VerifyingKey};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::Signature as p256ECDSA;
use p256::pkcs8::DecodePublicKey;
use shared_crypto::intent::{Intent, IntentMessage};
use sui_types::transaction::TransactionData;

use sui_types::crypto::SignatureScheme;
use yubikey::certificate::yubikey_signer::Signer;
use yubikey::piv::generate;
use yubikey::piv::sign_data;
use yubikey::piv::{AlgorithmId, RetiredSlotId, SlotId};
use yubikey::MgmKey;
use yubikey::{PinPolicy, TouchPolicy};

// Generates Secp256r1 key on Retired Slot 15 - TouchPolicy cached
// Prints our corresponding address
// Sign whatever base64 serialized tx data blidnly
// Prints out Sui Signature

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Transfer 0.1 SUI to another address
    let data = "AAABACD8TtqP+CanT90KxVMvAJOC0lecAdSsc417t+BpEqpWLwEBAQABAAD8TtqP+CanT90KxVMvAJOC0lecAdSsc417t+BpEqpWLwGWEY+N+TjwPj1XWX74uzh2/hLz/2CuA6EXzQXvRErZkgDE7wAAAAAAIHt/CrkuVzMPkhRiUl3+hQqx5M0ru3zpJkS65bnzn2hY/E7aj/gmp0/dCsVTLwCTgtJXnAHUrHONe7fgaRKqVi/oAwAAAAAAAICEHgAAAAAAAA==";
    let mut piv: yubikey::YubiKey = yubikey::YubiKey::open()?;

    //TODO Make this into clap option
    piv.authenticate(MgmKey::default())?;
    // let slot: SlotId = SlotId::Retired(RetiredSlotId::R15);
    let slot: SlotId = SlotId::Signature;

    let algorithm: AlgorithmId = AlgorithmId::EccP256;

    // let p = generate(
    //     &mut piv,
    //     slot,
    //     algorithm,
    //     PinPolicy::Once,
    //     TouchPolicy::Cached,
    // )?;
    println!("Key generated successfully in slot 15.");
    // End of TODO
    // println!("Public key: {:?}", p);
    // let cert = certificate::Certificate::read(&mut piv, slot);
    let metadata = yubikey::piv::metadata(&mut piv, slot)?;
    let temp_pub = metadata
        .public
        .ok_or_else(|| anyhow!("No public key information available."))?;

    let public_key_bytes = temp_pub
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| anyhow!("Public key bytes could not be retrieved."))?;

    let vk =
        p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key_bytes).expect("ecdsa key expected");
    let binding = vk.to_encoded_point(true);
    let pk_bytes = binding.as_bytes();
    println!("Public key bytes: {:?}", pk_bytes);

    let secp_pk = Secp256r1PublicKey::from_bytes(pk_bytes).unwrap();
    let mut sui_pk = vec![SignatureScheme::Secp256r1.flag()];
    sui_pk.extend(secp_pk.as_ref());
    println!("Secp256r1 Pubkey : {}", &secp_pk);
    println!("Sui Format Pubkey : {:?}", Base64::encode(&sui_pk));

    let mut suiaddress_hash = Blake2b256::new();
    suiaddress_hash.update(sui_pk);
    let sui_address = suiaddress_hash.finalize().digest;
    println!("Sui Address: 0x{}", Hex::encode(sui_address));

    println!("Raw tx_bytes to execute: {}", data);
    let msg: TransactionData = bcs::from_bytes(
        &Base64::decode(data)
            .map_err(|e| anyhow!("Cannot deserialize data as TransactionData {:?}", e))?,
    )?;
    let intent_msg = IntentMessage::new(Intent::sui_transaction(), msg);
    let mut hasher = Blake2b256::new();
    hasher.update(bcs::to_bytes(&intent_msg)?);
    let digest = hasher.finalize().digest;
    let digest_vec_bytes = digest.to_vec();

    let mut hasher2 = Sha256::default();
    hasher2.update(digest);
    let sha_digest = hasher2.finalize().digest;
    
    // // Using Default yubikey pin (TODO - add for user input)
    let _ = piv.verify_pin("123456".as_bytes());

    let sig_bytes = sign_data(&mut piv, &sha_digest, algorithm, slot).unwrap();
    println!("Signature bytes {:?}", sig_bytes);

    // the signature is ASN.1 BER encoded, there are 4 forms:
    // [48, 69, 2, 33, 0, 32_byte_r, 2, 33, 0, 32_byte_s]
    // [48, 69, 2, 33, 0, 32_byte_r, 2, 32, 32_byte_s]
    // [48, 69, 2, 32, 32_byte_r, 2, 33, 0, 32_byte_s]
    // [48, 69, 2, 32, 32_byte_r, 2, 32, 32_byte_s]
    let mut output = Vec::new();
    // the r bytes starts to read from either 4 or 5 depending on the length value at index 3
    if sig_bytes[3] == 33 {
        if sig_bytes[4] != 0 {
            panic!("Invalid form");
        }
        output.extend(&sig_bytes[5..(5 + 32)]);
    } else if sig_bytes[3] == 32 {
        output.extend(&sig_bytes[4..(4 + 32)]);
    } else {
        panic!("Invalid form");
    }
    // the last 32 bytes are s bytes
    output.extend(&sig_bytes[&sig_bytes.len() - 32..]);

    let sig = p256::ecdsa::Signature::from_slice(&output).unwrap();
    let normalized_sig = sig.normalize_s().unwrap_or(sig);
    println!("{:?}", sig);
    println!("{:?}", normalized_sig);

    let res = vk.verify(&digest_vec_bytes, &sig);
    let res_1 = vk.verify(&digest_vec_bytes, &normalized_sig);
    println!("p256 library verify result: {:?}", res);
    println!("p256 library verify normalized result: {:?}", res_1);

    let fc_sig = Secp256r1Signature::from_bytes(&output).unwrap();

    let normalized = fc_sig.sig.normalize_s().unwrap_or(sig);
    let fc_sig_normalized =
        Secp256r1Signature::from_bytes(normalized.to_bytes().as_slice()).unwrap();

    let fc_res = secp_pk.verify(&digest_vec_bytes, &fc_sig);
    let fc_res_1 = secp_pk.verify(&digest_vec_bytes, &fc_sig_normalized);
    println!("fastcrypto library verify result: {:?}", fc_res);
    println!(
        "fastcrypto library verify normalized result: {:?}",
        fc_res_1
    );

    let mut flag = vec![SignatureScheme::Secp256r1.flag()];
    flag.extend(normalized_sig.to_bytes());
    flag.extend(pk_bytes);

    let serialized_sig = Base64::encode(&flag);
    println!(
        "Serialized signature (`flag || sig || pk` in Base64): {:?}",
        serialized_sig
    );

    Ok(())
}
