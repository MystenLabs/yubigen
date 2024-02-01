use anyhow::anyhow;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::hash::{Blake2b256, HashFunction, Sha256, Sha3_256};
use fastcrypto::secp256r1::{Secp256r1PublicKey, Secp256r1Signature};
use fastcrypto::traits::{ToFromBytes, VerifyingKey};
use shared_crypto::intent::{Intent, IntentMessage};
use sui_types::transaction::TransactionData;
use tracing::info;

use clap::{error, Args, Parser, Subcommand};
use p256::ecdsa::signature::Verifier;
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
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    // Generate Key by default on RetiredSlot13, use --slot-id to choose retired slot 1-20
    GenerateKey(GenKeyArgs),
    Sign(SignData),
}

#[derive(Args, Clone)]
struct SignData {
    #[clap(long, short = 'd')]
    // The Serialized TransactionData to be passed for signing
    data: String,
    #[clap(long, short = 'p')]
    // Pin of your yubikey, uses default if not provided
    pin: Option<String>,
    #[clap(long, short = 's')]
    slot: Option<String>,
}

#[derive(Args, Clone)]
struct GenKeyArgs {
    #[clap(long, short = 'p')]
    pin: Option<String>,
    #[clap(long, short = 's')]
    slot: Option<String>,
    #[clap(long, short = 'm')]
    mgmt_key: Option<String>,
}
impl Commands {
    pub fn from_slot_input(input: u32) -> Option<RetiredSlotId> {
        match 20 - input + 1 {
            1 => Some(RetiredSlotId::R1),
            2 => Some(RetiredSlotId::R2),
            3 => Some(RetiredSlotId::R3),
            4 => Some(RetiredSlotId::R4),
            5 => Some(RetiredSlotId::R5),
            6 => Some(RetiredSlotId::R6),
            7 => Some(RetiredSlotId::R7),
            8 => Some(RetiredSlotId::R8),
            9 => Some(RetiredSlotId::R9),
            10 => Some(RetiredSlotId::R10),
            11 => Some(RetiredSlotId::R11),
            12 => Some(RetiredSlotId::R12),
            13 => Some(RetiredSlotId::R13),
            14 => Some(RetiredSlotId::R14),
            15 => Some(RetiredSlotId::R15),
            16 => Some(RetiredSlotId::R16),
            17 => Some(RetiredSlotId::R17),
            18 => Some(RetiredSlotId::R18),
            19 => Some(RetiredSlotId::R19),
            20 => Some(RetiredSlotId::R20),
            _ => None, // Return None for invalid inputs
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::GenerateKey(GenKeyArgs) => {
            let mut piv: yubikey::YubiKey = yubikey::YubiKey::open()?;
            let slot: SlotId;
            piv.authenticate(MgmKey::default())?;

            let algorithm: AlgorithmId = AlgorithmId::EccP256;

            // Todo Match Input=> RetiredSlotId
            let slot: SlotId = SlotId::Retired(RetiredSlotId::R13);
            println!("Generating Key on Retired Slot 13");

            let p = generate(
                &mut piv,
                slot,
                algorithm,
                PinPolicy::Once,
                TouchPolicy::Cached,
            )?;
            println!("Key generated successfully in slot 13");
            println!("Public key: {:?}", p);
            Ok(())
        }
        Commands::Sign(SignData) => {
            let data = &SignData.data;
            let mut piv: yubikey::YubiKey = yubikey::YubiKey::open()?;
            let slot: SlotId = SlotId::Retired(RetiredSlotId::R13);

            let algorithm: AlgorithmId = AlgorithmId::EccP256;

            let metadata = yubikey::piv::metadata(&mut piv, slot)?;
            let temp_pub = metadata
                .public
                .ok_or_else(|| anyhow!("No public key information available."))?;

            let public_key_bytes = temp_pub
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| anyhow!("Public key bytes could not be retrieved."))?;

            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key_bytes)
                .expect("ecdsa key expected");
            let binding = vk.to_encoded_point(true);
            let pk_bytes = binding.as_bytes();
            info!("Public key bytes: {:?}", pk_bytes);

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
                &Base64::decode(&data)
                    .map_err(|e| anyhow!("Cannot deserialize data as TransactionData {:?}", e))?,
            )?;
            let intent_msg = IntentMessage::new(Intent::sui_transaction(), msg);
            let mut hasher = Blake2b256::new();
            hasher.update(bcs::to_bytes(&intent_msg)?);
            let digest = hasher.finalize().digest;

            let mut hasher2 = Sha256::default();
            hasher2.update(digest);
            let sha_digest = hasher2.finalize().digest;

            // println!("Digest to sign: {:?}", Hex::encode(digest));
            let digest_vec_bytes = digest.to_vec();

            // // Using Default yubikey pin (TODO - add for user input)
            let _ = piv.verify_pin("123456".as_bytes());

            //let sig_bytes = sign_data(&mut piv, &digest_vec_bytes, algorithm, slot).unwrap();
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
            info!("{:?}", sig);
            info!("{:?}", normalized_sig);

            // TODO: Remove after refactor
            let res = vk.verify(&digest_vec_bytes, &sig);
            let res_1 = vk.verify(&digest_vec_bytes, &normalized_sig);
            info!("p256 library verify result: {:?}", res);
            info!("p256 library verify normalized result: {:?}", res_1);

            let fc_sig = Secp256r1Signature::from_bytes(&output).unwrap();

            let normalized = fc_sig.sig.normalize_s().unwrap_or(sig);
            let fc_sig_normalized =
                Secp256r1Signature::from_bytes(normalized.to_bytes().as_slice()).unwrap();

            let fc_res = secp_pk.verify(&digest_vec_bytes, &fc_sig);
            let fc_res_1 = secp_pk.verify(&digest_vec_bytes, &fc_sig_normalized);
            info!("fastcrypto library verify result: {:?}", fc_res);
            info!(
                "fastcrypto library verify normalized result: {:?}",
                fc_res_1
            );
            // End TODO
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
    }
}
