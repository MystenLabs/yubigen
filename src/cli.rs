use crate::types::*;
use crate::yubikey_handler::{
    from_slot_input, resolve_pin, SmartCard, YubiKeyHandler, YubiKeyInteractor,
};
use anyhow::{anyhow, Context};
use clap::{Args, Parser, Subcommand};
use serde_json::{json, Value};
use std::io::{self, BufRead};
use yubikey::piv::{RetiredSlotId, SlotId};
use yubikey::MgmKey;
use zeroize::ZeroizeOnDrop;

// Generates Secp256r1 key on Retired Slot 13(Default) - TouchPolicy cached
// Prints our corresponding address
// Sign whatever base64 serialized tx data blindly
// Prints out Sui Signature
// Requires Yubikey firmware > 5.3
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    // Generate Key by default on RetiredSlot13, use --slot-id to choose retired slot 1-20
    GenerateKey(GenKeyArgs),
    Sign(SignArgs),
    Call,
    // Prints the Sui Address for the key in the given slot (default R13)
    Address(AddressArgs),
}

#[derive(Args, Clone, ZeroizeOnDrop)]
pub struct SignArgs {
    #[clap(long, short = 'd')]
    // The Serialized TransactionData to be passed for signing
    pub data: String,
    #[clap(long, short = 'p')]
    // Pin of your yubikey, uses default if not provided
    pub pin: Option<String>,
    #[clap(long, short = 's')]
    pub slot: Option<String>,
}

#[derive(Args, Clone, ZeroizeOnDrop)]
pub struct AddressArgs {
    #[clap(long, short = 's')]
    pub slot: Option<String>,
}

#[derive(Args, Clone, ZeroizeOnDrop)]
pub struct GenKeyArgs {
    #[clap(long, short = 's')]
    pub slot: Option<String>,
    #[clap(long, short = 'm')]
    pub mgmt_key: Option<String>,
    #[clap(long, short = 'f')]
    pub force: bool,
}

pub fn execute(cli: Cli, device: Box<dyn SmartCard>) -> Result<(), Box<dyn std::error::Error>> {
    // Determine verbosity based on command
    let verbose = match &cli.command {
        Commands::Call => false,
        _ => true,
    };

    let mut handler = YubiKeyHandler::new_with_device(device, verbose);

    match &cli.command {
        Commands::GenerateKey(gen_key_args) => {
            let slot_id = match gen_key_args
                .slot
                .as_ref()
                .and_then(|s| s.parse::<u32>().ok())
            {
                Some(input) => {
                    from_slot_input(input).ok_or_else(|| anyhow!("Invalid slot number"))?
                }
                None => RetiredSlotId::R13, // Default to R13 if no slot is provided
            };
            let slot: SlotId = SlotId::Retired(slot_id);
            let m_key = match &gen_key_args.mgmt_key {
                Some(m) => MgmKey::from_bytes(m.as_str()),
                None => Ok(MgmKey::default()),
            }?;

            handler.generate_key(slot, Some(m_key), gen_key_args.force)?;
            Ok(())
        }
        Commands::Sign(sign_args) => {
            let data = &sign_args.data;
            let slot_id = match sign_args.slot.as_ref().and_then(|s| s.parse::<u32>().ok()) {
                Some(input) => {
                    from_slot_input(input).ok_or_else(|| anyhow!("Invalid slot number"))?
                }
                None => RetiredSlotId::R13, // Default to R13 if no slot is provided
            };
            let slot: SlotId = SlotId::Retired(slot_id);

            let pin = resolve_pin(sign_args.pin.clone());
            let _ = handler.sign_transaction(slot, data, &pin);
            Ok(())
        }
        Commands::Call => {
            let reader = io::stdin();
            let buf_reader = io::BufReader::new(reader);
            process_call_command(&mut handler, buf_reader)
        }
        Commands::Address(address_args) => {
            let slot_id = match address_args
                .slot
                .as_ref()
                .and_then(|s| s.parse::<u32>().ok())
            {
                Some(input) => {
                    from_slot_input(input).ok_or_else(|| anyhow!("Invalid slot number"))?
                }
                None => RetiredSlotId::R13, // Default to R13 if no slot is provided
            };
            let slot: SlotId = SlotId::Retired(slot_id);
            let response = handler.get_public_key(slot)?;
            println!("{}", response.sui_address);
            Ok(())
        }
    }
}

pub fn process_call_command<R: BufRead>(
    handler: &mut YubiKeyHandler,
    buf_reader: R,
) -> Result<(), Box<dyn std::error::Error>> {
    let JsonRpcRequest {
        jsonrpc: _,
        method,
        params,
        id,
    } = read_json_line(buf_reader).expect("Unable to deserialize request");

    if method.is_empty() {
        let e = anyhow::anyhow!("Method is required");
        return_error(&e.to_string(), id);
        return Err(e.into());
    }

    match handle_request(handler, &method, params) {
        Ok(result) => {
            let response = JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result,
                id,
            };
            println!("{}", serde_json::to_string(&response).unwrap());
            Ok(())
        }
        Err(e) => {
            return_error(&e.to_string(), id);
            Err(e.into())
        }
    }
}

pub fn read_json_line<R: BufRead>(mut buf_reader: R) -> Result<JsonRpcRequest, serde_json::Error> {
    let mut input = String::new();
    buf_reader.read_line(&mut input).unwrap();
    serde_json::from_str(&input)
}

fn handle_request(
    handler: &mut YubiKeyHandler,
    method: &str,
    params: Value,
) -> Result<Value, anyhow::Error> {
    match method {
        "sign" => {
            let args: SignParams =
                serde_json::from_value(params).context("Failed to deserialize sign params")?;
            let slot_id = args
                .key_id
                .parse::<u32>()
                .ok()
                .and_then(from_slot_input)
                .unwrap_or(RetiredSlotId::R13);
            let slot = SlotId::Retired(slot_id);

            let pin = resolve_pin(None);
            let signature = handler.sign_transaction(slot, &args.msg, &pin)?;

            Ok(serde_json::to_value(SignatureResponse { signature })?)
        }
        "keys" => {
            let mut keys = vec![];
            for i in 1..=20 {
                if let Some(slot_id) = from_slot_input(i) {
                    let slot = SlotId::Retired(slot_id);
                    if let Ok(resp) = handler.get_public_key(slot) {
                        keys.push(resp);
                    }
                }
            }
            Ok(serde_json::to_value(KeysResponse { keys })?)
        }
        "public_key" => {
            let args: PublicKeyParams = serde_json::from_value(params)
                .context("Failed to deserialize public_key params")?;
            let slot_id = args
                .key_id
                .parse::<u32>()
                .ok()
                .and_then(from_slot_input)
                .ok_or_else(|| anyhow!("Invalid key_id"))?;
            let slot = SlotId::Retired(slot_id);
            Ok(serde_json::to_value(handler.get_public_key(slot)?)?)
        }
        _ => Err(anyhow!("Invalid method: {}", method)),
    }
}

pub fn return_error(message: &str, id: u64) {
    println!(
        "{}",
        json!({
            "jsonrpc": "2.0",
            "error": {
                "code": 1,
                "message": message,
            },
            "id": id,
        })
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yubikey_handler::{DeviceMetadata, GeneratedKeyInfo, MockSmartCard};

    use mockall::predicate::*;
    use yubikey::piv::{AlgorithmId, RetiredSlotId, SlotId};
    use yubikey::{PinPolicy, TouchPolicy};

    use fastcrypto::encoding::{Base64, Encoding};
    use sui_types::base_types::{ObjectDigest, ObjectID, SequenceNumber, SuiAddress};
    use sui_types::transaction::{ProgrammableTransaction, TransactionData};

    // Valid P-256 public key (uncompressed)
    const VALID_PUBKEY: &[u8] = &[
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
        0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40,
        0x68, 0x37, 0xbf, 0x51, 0xf5,
    ];

    #[test]
    fn test_execute_generate_key() {
        let mut mock_device = MockSmartCard::new();

        mock_device
            .expect_authenticate()
            .with(always())
            .times(1)
            .returning(|_| Ok(()));

        mock_device
            .expect_generate()
            .with(
                eq(SlotId::Retired(RetiredSlotId::R13)),
                eq(AlgorithmId::EccP256),
                eq(PinPolicy::Once),
                eq(TouchPolicy::Always),
            )
            .times(1)
            .returning(|_, _, _, _| {
                Ok(GeneratedKeyInfo {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            });

        mock_device.expect_metadata().returning(|_| {
            Ok(DeviceMetadata {
                public_key: VALID_PUBKEY.to_vec(),
            })
        }); // Used for existence check or logging

        let cli = Cli {
            command: Commands::GenerateKey(GenKeyArgs {
                slot: None,
                mgmt_key: None,
                force: true,
            }),
        };

        execute(cli, Box::new(mock_device)).unwrap();
    }

    #[test]
    fn test_execute_sign() {
        let mut mock_device = MockSmartCard::new();

        // Mock verification
        mock_device
            .expect_verify_pin()
            .with(eq("123456".as_bytes()))
            .times(1)
            .returning(|_| Ok(()));

        mock_device.expect_metadata().returning(|_| {
            Ok(DeviceMetadata {
                public_key: VALID_PUBKEY.to_vec(),
            })
        });

        // Construct valid TransactionData
        let pt = ProgrammableTransaction {
            inputs: vec![],
            commands: vec![],
        };
        let sender = SuiAddress::ZERO;
        let gas_payment = vec![(
            ObjectID::ZERO,
            SequenceNumber::from_u64(1),
            ObjectDigest::new([0; 32]),
        )];

        let tx_data = TransactionData::new_programmable(sender, gas_payment, pt, 1000, 1);
        let tx_bytes = bcs::to_bytes(&tx_data).unwrap();
        let tx_base64 = Base64::encode(&tx_bytes);

        mock_device
            .expect_sign_data()
            .with(
                function(|digest: &[u8]| digest.len() == 32),
                eq(AlgorithmId::EccP256),
                eq(SlotId::Retired(RetiredSlotId::R13)),
            )
            .times(1)
            .returning(|_, _, _| {
                Ok(vec![
                    // Valid ASN.1 signature (dummy)
                    0x30, 0x44, 0x02, 0x20, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x20, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01,
                ])
            });

        let cli = Cli {
            command: Commands::Sign(SignArgs {
                data: tx_base64,
                pin: Some("123456".to_string()),
                slot: None,
            }),
        };

        execute(cli, Box::new(mock_device)).unwrap();
    }

    #[test]
    fn test_handle_request_public_key() {
        let mut mock_device = MockSmartCard::new();
        mock_device
            .expect_metadata()
            .with(eq(SlotId::Retired(RetiredSlotId::R13)))
            .returning(|_| {
                Ok(DeviceMetadata {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            });

        let mut handler = YubiKeyHandler::new_with_device(Box::new(mock_device), false);

        let params = json!({
            "key_id": "13"
        });

        let result = handle_request(&mut handler, "public_key", params).unwrap();
        let resp: PublicKeyResponse = serde_json::from_value(result).unwrap();
        assert_eq!(resp.key_id, "13");
        assert!(resp.sui_address.starts_with("0x"));
    }

    #[test]
    fn test_handle_request_keys() {
        let mut mock_device = MockSmartCard::new();
        // Since it iterates 1..20, and likely some fail or some succeed.
        // We'll mock returning a key for R13 and error (or empty) for others.
        // Or we can just mock R13 specifically and let others default if the mock allows fallback or we need expectations for all.
        // Mockall strictness might require expectations for ALL calls unless we use `returning` with a catch-all or partial.
        // Best approach: Mock R1 always returning Ok, R13 Ok. Others Err.
        // Actually, logic is: if let Ok(resp) = handler.get_public_key(slot).
        // get_public_key calls metadata.

        mock_device
            .expect_metadata()
            .with(eq(SlotId::Retired(RetiredSlotId::R1)))
            .returning(|_| {
                Ok(DeviceMetadata {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            });

        mock_device
            .expect_metadata()
            .with(eq(SlotId::Retired(RetiredSlotId::R13)))
            .returning(|_| {
                Ok(DeviceMetadata {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            });

        // For all other slots, return Error. matching anything else?
        // Mockall doesn't support "anything else" easily with `with`.
        // We can use a single expect_metadata with a closure that checks slot.
        mock_device.expect_metadata().returning(|slot| {
            if slot == SlotId::Retired(RetiredSlotId::R1)
                || slot == SlotId::Retired(RetiredSlotId::R13)
            {
                Ok(DeviceMetadata {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            } else {
                Err(anyhow::anyhow!("Not found").into())
            }
        });

        let mut handler = YubiKeyHandler::new_with_device(Box::new(mock_device), false);
        let params = json!({});

        let result = handle_request(&mut handler, "keys", params).unwrap();
        let resp: KeysResponse = serde_json::from_value(result).unwrap();
        assert_eq!(resp.keys.len(), 2);
    }

    #[test]
    fn test_handle_request_sign() {
        // Similar to test_execute_sign but via RPC params
        let mut mock_device = MockSmartCard::new();
        mock_device.expect_verify_pin().returning(|_| Ok(()));
        mock_device.expect_metadata().returning(|_| {
            Ok(DeviceMetadata {
                public_key: VALID_PUBKEY.to_vec(),
            })
        });

        // Valid dummy TransactionData
        let pt = ProgrammableTransaction {
            inputs: vec![],
            commands: vec![],
        };
        let sender = SuiAddress::ZERO;
        let gas_payment = vec![(
            ObjectID::ZERO,
            SequenceNumber::from_u64(1),
            ObjectDigest::new([0; 32]),
        )];
        let tx_data = TransactionData::new_programmable(sender, gas_payment, pt, 1000, 1);
        let tx_base64 = Base64::encode(&bcs::to_bytes(&tx_data).unwrap());

        mock_device.expect_sign_data().returning(|_, _, _| {
            Ok(vec![
                0x30, 0x44, 0x02, 0x20, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x20, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01,
            ])
        });

        let mut handler = YubiKeyHandler::new_with_device(Box::new(mock_device), false);
        let params = json!({
            "key_id": "13",
            "msg": tx_base64
        });

        let result = handle_request(&mut handler, "sign", params).unwrap();
        let resp: SignatureResponse = serde_json::from_value(result).unwrap();
        assert!(!resp.signature.is_empty());
    }

    #[test]
    fn test_execute_invalid_slot() {
        let mock_device = MockSmartCard::new();
        // Slot "99" is invalid
        let cli = Cli {
            command: Commands::GenerateKey(GenKeyArgs {
                slot: Some("99".to_string()),
                mgmt_key: None,
                force: true,
            }),
        };
        let result = execute(cli, Box::new(mock_device));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Invalid slot number");

        let mock_device2 = MockSmartCard::new();
        let cli_sign = Cli {
            command: Commands::Sign(SignArgs {
                data: "dummy".to_string(),
                pin: None,
                slot: Some("99".to_string()),
            }),
        };
        // We need a fresh mock for sign because execute consumes the box.
        let result_sign = execute(cli_sign, Box::new(mock_device2));
        assert!(result_sign.is_err());
        assert_eq!(result_sign.unwrap_err().to_string(), "Invalid slot number");
    }

    #[test]
    fn test_process_call_command() {
        let mut mock_device = MockSmartCard::new();
        mock_device
            .expect_metadata()
            .with(eq(SlotId::Retired(RetiredSlotId::R13)))
            .returning(|_| {
                Ok(DeviceMetadata {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            });

        let mut handler = YubiKeyHandler::new_with_device(Box::new(mock_device), false);

        // Prepare input: a valid JSON-RPC request for "public_key"
        let input_json = json!({
            "jsonrpc": "2.0",
            "method": "public_key",
            "params": {
                "key_id": "13"
            },
            "id": 1
        })
        .to_string();

        // Add newline because read_json_line uses read_line
        let input = format!("{}\n", input_json);
        let cursor = std::io::Cursor::new(input);

        // We can capture stdout if we really want to check the output, but for now we check it returns Ok
        let result = process_call_command(&mut handler, cursor);
        assert!(result.is_ok());
    }
    #[test]
    fn test_execute_address() {
        let mut mock_device = MockSmartCard::new();
        mock_device
            .expect_metadata()
            .with(eq(SlotId::Retired(RetiredSlotId::R13)))
            .returning(|_| {
                Ok(DeviceMetadata {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            });

        let cli = Cli {
            command: Commands::Address(AddressArgs { slot: None }),
        };

        execute(cli, Box::new(mock_device)).unwrap();
    }
}
