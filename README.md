# Yubigen Signer

EXPERIMENTAL use at own risk.

## Install the Signer

Add this repo to your local `PATH`.

```bash
git clone -b modular-signer git@github.com:MystenLabs/yubigen.git
cd yubigen
cargo install --path .
```

## Install the CLI Branch

Install the `external-keys-cli-support` branch of the Sui CLI to use the external keys feature.

```bash
suiup install --nightly external-keys-cli-support sui
```

## Yubigen CLI Commands

```
Usage: yubigen <COMMAND>

Commands:
  generate-key  Generate Key by default on RetiredSlot13, use --slot-id to choose retired slot 1-20
  sign          Sign a transaction digest
  call          JSON-RPC mode for integration with Sui CLI (reads from stdin)
  address       Prints the Sui Address for the key in the given slot (default R13)
  help          Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

`cargo run sign --data "<Base64 TX Bytes"` -> Must Generate key before on R13 Slot

## Add A Key (Example from Ledger Signer - Adapt for Yubigen)

First ensure your YubiKey is connected.

```bash
sui external-keys list-keys yubigen
# ... output similar to:
# ╭────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
# │ keyId     │ ...                                                                                          │
# │ suiAddress│ 0x...                                                                                        │
# ...

sui external-keys add-existing "key-id-or-path" yubigen
# OR
sui external-keys generate yubigen
```

## Use the Key

Set your new key as active

```bash
sui client swap --address <YOUR_SUI_ADDRESS>
sui client transfer --object-id [object-id] --to [to address]
```
