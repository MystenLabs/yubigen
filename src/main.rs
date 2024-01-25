use anyhow::anyhow;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::hash::{Blake2b256, HashFunction};
use fastcrypto::secp256r1::{Secp256r1PublicKey, Secp256r1Signature};
use fastcrypto::traits::ToFromBytes;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, PointConversionForm};
use openssl::nid::Nid;
use openssl::{ec::*, ecdsa};
use p256::ecdsa::Signature as p256ECDSA;
use shared_crypto::intent::{Intent, IntentMessage};
use sui_types::transaction::TransactionData;

use sui_types::crypto::SignatureScheme;
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
    let intent: Option<Intent> = Some(Intent::sui_transaction());
    // Transfer 0.3 SUI to another address
    let data = "AAABACD8TtqP+CanT90KxVMvAJOC0lecAdSsc417t+BpEqpWLwEBAQABAAAXFE15UBdSutUsZGTXCCYUTGFyjcexychiYuQv+ByROwFbIZwV8zrImgud56DJItcPVVTuVTA15T9s8sDtGvvWU/3D7wAAAAAAIHtAkzZ9ZIPSYXZlTG9cnFNZho15hET8Bc5vllYEzvHAFxRNeVAXUrrVLGRk1wgmFExhco3HscnIYmLkL/gckTvoAwAAAAAAAICEHgAAAAAAAA=="  ;
    let mut piv: yubikey::YubiKey = yubikey::YubiKey::open()?;

    //TODO Make this into clap option
    piv.authenticate(MgmKey::default())?;
    let slot: SlotId = SlotId::Retired(RetiredSlotId::R15);
    // let slot: SlotId = SlotId::Signature;

    let algorithm: AlgorithmId = AlgorithmId::EccP256;

    // let p = generate(
    //     &mut piv,
    //     slot,
    //     algorithm,
    //     PinPolicy::Once,
    //     TouchPolicy::Cached,
    // )?;
    // println!("Key generated successfully in slot 15.");

    // End of TODO

    // let cert = certificate::Certificate::read(&mut piv, slot);
    let metadata = yubikey::piv::metadata(&mut piv, slot)?;

    let mut ctx = BigNumContext::new()?;
    let temp_pub = metadata
        .public
        .ok_or_else(|| anyhow!("No public key information available."))?;

    let public_key_bytes = temp_pub
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| anyhow!("Public key bytes could not be retrieved."))?;

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let point = EcPoint::from_bytes(&group, &public_key_bytes, &mut ctx)?;
    let pkey = EcKey::from_public_key(&group, &point)?;
    let pkey_compact_result =
        pkey.public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx);
    let pkey_compact = pkey_compact_result.unwrap();

    let secp_pk = Secp256r1PublicKey::from_bytes(&pkey_compact).unwrap();
    println!("Secp256r1 Sui Pubkey : {}", &secp_pk);

    let mut suiaddress_hash = Blake2b256::new();
    suiaddress_hash.update(secp_pk);
    let sui_address = suiaddress_hash.finalize().digest;
    println!("(Wrong) Sui Address: 0x{}", Hex::encode(sui_address));

    println!("Raw tx_bytes to execute: {}", data);
    let intent = intent.unwrap_or_else(Intent::sui_transaction);
    //println!("Intent: {:?}", intent);
    let msg: TransactionData = bcs::from_bytes(
        &Base64::decode(&data)
            .map_err(|e| anyhow!("Cannot deserialize data as TransactionData {:?}", e))?,
    )?;
    let intent_msg = IntentMessage::new(intent, msg);
    // println!(
    //     "Raw intent message: {:?}",
    //     Base64::encode(bcs::to_bytes(&intent_msg)?)
    // );

    let mut hasher = Blake2b256::new();
    hasher.update(bcs::to_bytes(&intent_msg)?);
    let digest = hasher.finalize().digest;
    println!("Digest to sign: {:?}", Base64::encode(digest));
    let digest_vec_bytes = digest.to_vec();
    //println!("Digest vect {:?}", digest_vec_bytes);

    // Using Default yubikey pin (TODO - add for user input)
    piv.verify_pin("123456".as_bytes());
    let sig_bytes = sign_data(&mut piv, &digest_vec_bytes, algorithm, slot);
    let sig_bytes_der: &[u8] = &sig_bytes.map(|b| b.to_vec()).unwrap_or_default();
    // println!("{:?}", sig_bytes_der);

    let secpsig = p256ECDSA::from_der(sig_bytes_der)?;
    let normalized_sig = secpsig
        .normalize_s()
        .expect("ECDSA Signature Not found")
        .to_bytes();

    println!("Un-Normalized Sig Bytes {:?}", secpsig.to_bytes());
    println!("Normalized Sig Bytes {:?}", normalized_sig);
    println!("Public Key Compact bytes {:?}", pkey_compact);

    let mut flag = vec![SignatureScheme::Secp256r1.flag()];
    flag.extend(normalized_sig);
    flag.extend(pkey_compact);

    let serialized_sig = Base64::encode(&flag);
    println!(
        "Serialized signature (`flag || sig || pk` in Base64): {:?}",
        serialized_sig
    );

    Ok(())
}
