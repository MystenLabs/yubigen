use anyhow::Error;
pub use device::YubiKeyHandler;
use mockall::automock;
use std::env;
use yubikey::piv::AlgorithmId;
use yubikey::piv::RetiredSlotId;
use yubikey::piv::SlotId;
use yubikey::{MgmKey, PinPolicy, TouchPolicy};

pub mod device;

#[derive(Debug, Clone)]
pub struct DeviceMetadata {
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct GeneratedKeyInfo {
    pub public_key: Vec<u8>,
}

#[automock]
pub trait SmartCard {
    fn authenticate(&mut self, key: MgmKey) -> Result<(), Error>;
    fn metadata(&mut self, slot: SlotId) -> Result<DeviceMetadata, Error>;
    fn generate(
        &mut self,
        slot: SlotId,
        alg: AlgorithmId,
        pin_policy: PinPolicy,
        touch_policy: TouchPolicy,
    ) -> Result<GeneratedKeyInfo, Error>;
    fn sign_data(
        &mut self,
        digest: &[u8],
        alg: AlgorithmId,
        slot: SlotId,
    ) -> Result<Vec<u8>, Error>;
    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), Error>;
}

pub fn from_slot_input(input: u32) -> Option<RetiredSlotId> {
    match input {
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

pub fn resolve_pin(explicit_pin: Option<String>) -> String {
    if let Some(p) = explicit_pin {
        return p;
    }
    if let Ok(p) = env::var("YUBIGEN_PIN") {
        return p;
    }
    "123456".to_string()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use mockall::predicate::*;
    use serial_test::serial;
    use std::env;
    use yubikey::piv::{AlgorithmId, SlotId};
    use yubikey::MgmKey;

    use fastcrypto::encoding::{Base64, Encoding};
    use sui_types::base_types::{ObjectDigest, ObjectID, SequenceNumber, SuiAddress};
    use sui_types::transaction::{ProgrammableTransaction, TransactionData};

    // Helper to reset env var
    fn reset_env() {
        env::remove_var("YUBIGEN_PIN");
    }

    #[test]
    #[serial]
    fn test_resolve_pin_explicit() {
        reset_env();
        let pin = resolve_pin(Some("123456".to_string()));
        assert_eq!(pin, "123456");
    }

    #[test]
    #[serial]
    fn test_resolve_pin_env() {
        reset_env();
        env::set_var("YUBIGEN_PIN", "env_pin");
        let pin = resolve_pin(None);
        assert_eq!(pin, "env_pin");
    }

    #[test]
    #[serial]
    fn test_resolve_pin_priority() {
        reset_env();
        env::set_var("YUBIGEN_PIN", "env_pin");
        let pin = resolve_pin(Some("explicit_pin".to_string()));
        assert_eq!(pin, "explicit_pin");
    }

    #[test]
    fn test_from_slot_input() {
        // Test all valid inputs
        assert_eq!(from_slot_input(1), Some(RetiredSlotId::R1));
        assert_eq!(from_slot_input(20), Some(RetiredSlotId::R20));

        // Test invalid inputs
        assert_eq!(from_slot_input(0), None);
        assert_eq!(from_slot_input(21), None);
    }

    #[test]
    #[serial]
    fn test_resolve_pin_default() {
        reset_env();
        let pin = resolve_pin(None);
        assert_eq!(pin, "123456");
    }

    // Valid P-256 public key (uncompressed)
    const VALID_PUBKEY: &[u8] = &[
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
        0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
        0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a,
        0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40,
        0x68, 0x37, 0xbf, 0x51, 0xf5,
    ];

    #[test]
    fn test_generate_key() {
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
                eq(PinPolicy::Once),     // Fixed: Implementation uses Once
                eq(TouchPolicy::Always), // Fixed: Implementation uses Always
            )
            .times(1)
            .returning(|_, _, _, _| {
                Ok(GeneratedKeyInfo {
                    public_key: VALID_PUBKEY.to_vec(), // Fixed: Valid P-256 key
                })
            });

        mock_device
            .expect_metadata()
            .with(eq(SlotId::Retired(RetiredSlotId::R13)))
            .times(1)
            .returning(|_| {
                Ok(DeviceMetadata {
                    public_key: VALID_PUBKEY.to_vec(),
                })
            });

        let mut handler = YubiKeyHandler::new_with_device(Box::new(mock_device), false);
        // Set force=true to avoid "Key already exists" error
        handler
            .generate_key(
                SlotId::Retired(RetiredSlotId::R13),
                Some(MgmKey::default()),
                true,
            )
            .unwrap();
    }

    #[test]
    fn test_sign_transaction() {
        let mut mock_device = MockSmartCard::new();

        mock_device
            .expect_verify_pin()
            .with(eq("123456".as_bytes()))
            .times(1)
            .returning(|_| Ok(()));

        // Expect metadata call (used for logging or checks)
        mock_device
            .expect_metadata()
            .with(eq(SlotId::Retired(RetiredSlotId::R13)))
            .returning(|_| {
                Ok(DeviceMetadata {
                    public_key: VALID_PUBKEY.to_vec(), // Fixed: Valid P-256 key
                })
            });

        // Construct valid TransactionData
        let pt = ProgrammableTransaction {
            inputs: vec![],
            commands: vec![],
        };
        // TransactionData::new_programmable takes ProgrammableTransaction directly
        let sender = SuiAddress::ZERO;
        // Gas payment is Vec<ObjectRef> aka Vec<(ObjectID, SequenceNumber, ObjectDigest)>
        let gas_payment = vec![(
            ObjectID::ZERO,
            SequenceNumber::from_u64(1),
            ObjectDigest::new([0; 32]),
        )];

        let tx_data = TransactionData::new_programmable(
            sender,
            gas_payment,
            pt,
            1000, // gas_budget
            1,    // gas_price
        );
        let tx_bytes = bcs::to_bytes(&tx_data).unwrap();
        let tx_base64 = Base64::encode(&tx_bytes);

        // SHA256 of the intent message digest... hard to predict without hashing the exact tx_data.
        // We will just match ANY digest of 32 bytes again.
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
                    0x30, 0x44, 0x02, 0x20, // Integers
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x20, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01,
                ])
            });

        let mut handler = YubiKeyHandler::new_with_device(Box::new(mock_device), false);

        let signature = handler
            .sign_transaction(SlotId::Retired(RetiredSlotId::R13), &tx_base64, "123456")
            .unwrap();

        assert!(!signature.is_empty());
    }
}
