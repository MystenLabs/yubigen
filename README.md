1. Uncomment the generate block around L39-46 to generate a Secp256r1 key in Signature slot of yubikey 9c. Comment out if you do not want to generate a new key.Error: NotFound means you do not have a key generated on the slot
2. piv.authenticate() L33 uses the default management key - if you have a different management key this needs to be changed out
3. sign_data() function L98 signs the "hello" message
4. cargo run
