# psbt_flow

PSBT signing by example

# Wallet keys

## Recovery phrase ([BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)):

Converted from raw 128-bit entropy (all zeroes in this case) by appending a hash-based checksum - take first 4 bits of sha256(entropy), split resulting 132 bits to 11-bit chunks and convert each chunk to a word from the 2048-word dictionary:

```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

## [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) seed (with empty BIP39 password):

Derived by applying pbkdf2-hmac-sha512 to the mnemonic with `"mnemonic"+password` as a salt using 2048 iterations:

```
5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
```

## Root BIP32 key:

Output of the `hmac-sha512("Bitcoin seed", seed)` is splitted in two parts, first part is a root private key, second part is the chain code.

```
Mainnet: xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu
Testnet: tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd
```

## Master fingerprint of the root key, used to detect pubkeys in PSBT that are derived from this root:

Fingerprint is calculated from the root key by applying `hash160() = ripemd160(sha256())` to the sec-serialized public key of the root key. Sec-serialized public key has a length of 33 bytes (compressed representation).

```
Fingerprint: 73c5da0a
```

## BIP-32 derivation

Deriving `m/49'/1'/0'/1/0` key from root key above ([specs](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Private_parent_key_rarr_private_child_key)):

```
root = xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu
decoding it:
chain code: 7923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e
secret: 1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67

Child with index 49' (hardened):
index = 0x80000000 + 49 = 80000031 in big endian

For hardened derivation we use private key in the hash:

child_tweak, child_chain_code = hmac-sha512(chain_code, <00><priv_key><index>)
hmac-sha512(7923408dadd3c7b56eed15567707ae5e5dca089de972e07f3b860450e2a3b70e, 001837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf6780000031)
result:
6a3ececfca6e6b1eabd5167925467858ae4451894a83fddc88aa966a438ce413fe82159c44da72e34203f1215d494638d17a1ee587db3d11651654ac4e2b1ff3
child chain_code: fe82159c44da72e34203f1215d494638d17a1ee587db3d11651654ac4e2b1ff3
private key tweak: 6a3ececfca6e6b1eabd5167925467858ae4451894a83fddc88aa966a438ce413
child private key = parent private key + tweak = 8276908e5898010abda2b9298b5b943b7df8dc68e8cbaf2e5d15711de5a9c37a

Next step - index 1' (80000001 in big endian)
chain code: 3b0af4d37b373d810fcf34cdf2e87cf68df5022812768d7d28d4451dc30e8951
private key: 7eae2f0d227922ea9e95d7577a2d31a25b22a43be6856749db6eb5e220dabeea

Next - index 0' (80000000 in big endian):
chain code: 29493969d5af07bdca312802a84f43f87f2522ee84d4f880947d10849675bd3d
secret: 25411fe7b0d083e9265a2d0f29ce7b10eb9c5570306144c77f0f4dfe9238747e

Next - index 1 (00000001 in big endian), it's not hardened so we use public key in hmac:
child_tweak, child_chain_code = hmac-sha512(chain_code, <public_key><index>)
hmac-sha512(29493969d5af07bdca312802a84f43f87f2522ee84d4f880947d10849675bd3d, 0262c1521f5fd87bbb4055f9f6e866d3eaebd179d5bfb9adac3aec682f12948a6700000001)
result:
5f51bb0ce3f1ae23ebec65614a3308f3bb0eeead9d5af6dc4e400759673dac2591fab97e3048e663e757405b7b37e476ccb7aa765a0d1ce90908c4fc325c01c8
child chain_code: 91fab97e3048e663e757405b7b37e476ccb7aa765a0d1ce90908c4fc325c01c8
private key tweak: 5f51bb0ce3f1ae23ebec65614a3308f3bb0eeead9d5af6dc4e400759673dac25
child private key = parent private key + tweak = 8492daf494c2320d1246927074018404a6ab441dcdbc3ba3cd4f5557f97620a3

Next - index 0 (00000000 in be), not hardened:
chain code: 6016fd78e15211b3260f67911dbe28f59889e471b6f05547ef39f3f98ba85825
private key: f0f6c08500d34c351d14434589913c50e56e03c41e399488db476114c487053f
```

# Example PSBT

Assuming here a Bitcoin wallet that uses a single-key policy with the root key from above, using wrapped-segwit addresses and derivation path for regtest `m/49'/1'/0'/{0,1}/*`. This derivation path standard is defined in [BIP-49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki). For different address types it is recommended to use [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) for legacy addresses, [BIP-49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki) for wrapped segwit, [BIP-84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki) for native segwit.

## Base64-encoded PSBT:

This PSBT is spending two inputs - from receiving addresses with indexes 0 and 1 of the wallet, and has two outputs - output 0 goes back to change address #0 and output 1 goes to external address `bcrt1qydtsw90p4smqkztaxfup6t2hr7w9mzs8mt68ccnurc00kfxtttqqxlges6`, the fee is 266 bytes:

```
cHNidP8BAKcCAAAAAhy21k6/lcoj6dYme5JdvRjDk19pGoZ/O4OquPjXRdhcAQAAAAD9////6g2Nk+ObJ+nH+3bdvBIqsgkmMNdFiTPTXyltvwra8McAAAAAAP3///8C9gc9AAAAAAAXqRQlHdEUV6JZw7pH5cyjcX/kIU4CmIfA2KcAAAAAACIAICNXBxXhrDYLCX0yeB0tVx+cXYoH2vR8YnweHvsky1rA2QAAAAABAHICAAAAAdqaS4Kq2IAX8kqlREL9tohEwkNBzSF64RpIIxL0YlOjAQAAAAD+////Alji3iIBAAAAFgAUQ5WpqejZobzUS49CW0p3nPMkV3OAlpgAAAAAABepFDNsqhPgi5YICjK12BjVm0qzs2dChwAAAAABASCAlpgAAAAAABepFDNsqhPgi5YICjK12BjVm0qzs2dChwEEFgAUOJcfc5MPbBQdl3rE/UpyfIVJNbMiBgOhr4BKwQiopReCGYwtA0sov5DIgD9aU/didvpppOrnfxhzxdoKMQAAgAEAAIAAAACAAAAAAAAAAAAAAQByAgAAAAHw8+Znx3tHgVAG2s23K+8Hvb6aNvocYolsRpzzJMC4/gEAAAAA/v///wJAS0wAAAAAABepFIHXS804DAX3kdH0yBg3Vl3smyNKh5nEwyMBAAAAFgAUOaRgB4EiNS4w6LlSDhbdYD85OVEAAAAAAQEgQEtMAAAAAAAXqRSB10vNOAwF95HR9MgYN1Zd7JsjSocBBBYAFL18ec12pUkfARFbgTcs3JsFztsAIgYDsi01fWSqDBDK/82usi/KKCsx8BHIwsjG1eVqZ21SyAMYc8XaCjEAAIABAACAAAAAgAAAAAABAAAAAAEAFgAUcL6x4EpQCUDp86uqZuGkmsVbjzUiAgKi/ImWxSYiSLXa78Wk0M3NAMEwR9DLEwKBNupjDYdahxhzxdoKMQAAgAEAAIAAAACAAQAAAAAAAAAAAA==
```

## Hex-encoded PSBT:

```
70736274ff0100a702000000021cb6d64ebf95ca23e9d6267b925dbd18c3935f691a867f3b83aab8f8d745d85c0100000000fdffffffea0d8d93e39b27e9c7fb76ddbc122ab2092630d7458933d35f296dbf0adaf0c70000000000fdffffff02f6073d000000000017a914251dd11457a259c3ba47e5cca3717fe4214e029887c0d8a7000000000022002023570715e1ac360b097d32781d2d571f9c5d8a07daf47c627c1e1efb24cb5ac0d9000000000100720200000001da9a4b82aad88017f24aa54442fdb68844c24341cd217ae11a482312f46253a30100000000feffffff0258e2de22010000001600144395a9a9e8d9a1bcd44b8f425b4a779cf3245773809698000000000017a914336caa13e08b96080a32b5d818d59b4ab3b367428700000000010120809698000000000017a914336caa13e08b96080a32b5d818d59b4ab3b3674287010416001438971f73930f6c141d977ac4fd4a727c854935b3220603a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f1873c5da0a3100008001000080000000800000000000000000000100720200000001f0f3e667c77b47815006dacdb72bef07bdbe9a36fa1c62896c469cf324c0b8fe0100000000feffffff02404b4c000000000017a91481d74bcd380c05f791d1f4c81837565dec9b234a8799c4c3230100000016001439a460078122352e30e8b9520e16dd603f39395100000000010120404b4c000000000017a91481d74bcd380c05f791d1f4c81837565dec9b234a870104160014bd7c79cd76a5491f01115b81372cdc9b05cedb00220603b22d357d64aa0c10caffcdaeb22fca282b31f011c8c2c8c6d5e56a676d52c8031873c5da0a310000800100008000000080000000000100000000010016001470beb1e04a500940e9f3abaa66e1a49ac55b8f35220202a2fc8996c5262248b5daefc5a4d0cdcd00c13047d0cb13028136ea630d875a871873c5da0a31000080010000800000008001000000000000000000
```

## PSBT splitted to fields:

PSBT has three scopes - global, per-input and per-output, and contains all metadata needed for the hardware wallet to verify and sign transaction. Global scope contains a raw unsigned bitcoin transaction, per-input and per-output scopes contain extra data like bip32 derivation paths, witness scripts and other stuff. Per input scopes also contain information about utxos it is spending (amount and scriptpubkey).

```
# PSBT magic b"psbt\xff"
70736274ff
===== GLOBAL SCOPE =======
# key 00, global transaction - unsigned raw bitcoin transaction
01 00
# transaction itself
a7 - length of the transaction field
  02000000 - version, little-endian (version = 2)
  ---- inputs -----
  02 - number of inputs
  ---- input 0 ----
  1cb6d64ebf95ca23e9d6267b925dbd18c3935f691a867f3b83aab8f8d745d85c - previous tx hash (reversed txid of the transaction we are spending)
  01000000 - prev vout, little-endian (vout = 1)
  00 - scriptsig, empty because transaction is unsigned
  fdffffff - sequence number, little endian
  ---- input 1 ----
  ea0d8d93e39b27e9c7fb76ddbc122ab2092630d7458933d35f296dbf0adaf0c7 - prev tx hash
  00000000 - prev vout
  00 - scriptsig
  fdffffff - sequence number
  ---- outputs -----
  02 - 2 outputs
  ---- output 0 ----
  f6073d0000000000 - amount, 8-byte little endian, 3999734 sats
  17a914251dd11457a259c3ba47e5cca3717fe4214e029887 - scriptpubkey of the output, address - 2MvdUi5o3f2tnEFh9yGvta6FzptTZtkPJC8
  ---- output 1 ----
  c0d8a70000000000 - amount, 11000000 sats
  22002023570715e1ac360b097d32781d2d571f9c5d8a07daf47c627c1e1efb24cb5ac0 - scriptpubkey of the output, (addr bcrt1qydtsw90p4smqkztaxfup6t2hr7w9mzs8mt68ccnurc00kfxtttqqxlges6 on regtest)
d9000000 - locktime

00 - end of global scope

============== INPUT SCOPES =================
---------- INPUT 0 --------------
# non_witness_utxo - full previous transaction. We can verify that this transaction hashes to the same tx hash as in input 0 of global transaction, and drop everything except output 1 - there we can get amount and scriptpubkey for signing.
# non witness utxo key
01 00
# non witness utxo value - full previous transaction
72 0200000001da9a4b82aad88017f24aa54442fdb68844c24341cd217ae11a482312f46253a30100000000feffffff0258e2de22010000001600144395a9a9e8d9a1bcd44b8f425b4a779cf3245773809698000000000017a914336caa13e08b96080a32b5d818d59b4ab3b367428700000000
------
# witness utxo - only output that we need for signing with segwit. Present only in segwit transaction, currently in most cases for segwit transaction both non_witness_utxo and witness_utxo are present, but sometimes wallets keep only witness_utxo.
# witness-utxo key
01 01
# witness-utxo value
20 - length of the witness utxo
  8096980000000000 - amount, little endian, 8 bytes. 10000000 sats
  17a914336caa13e08b96080a32b5d818d59b4ab3b3674287 - scriptpubkey (addr - 2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2)
# redeem script, when finalizing transcation we need to put this to scriptpubkey.
01 04 - redeem script key
16 001438971f73930f6c141d977ac4fd4a727c854935b3 - redeem script value
# bip32 derivation. Key is the public key, value is the derivation (key: <len><0x06><pubkey>)
22 06 03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f - pubkey
18 - length of derivation value, derivation path - fingerprint 73c5da0a, derivation m/49'/1'/0'/0/0
  73c5da0a - fingerprint
  31000080 - 49'
  01000080 - 1'
  00000080 - 0'
  00000000 - 0
  00000000 - 0
00 - end of scope
---------- INPUT 1 --------------
# similar to input 0, same fields
0100720200000001f0f3e667c77b47815006dacdb72bef07bdbe9a36fa1c62896c469cf324c0b8fe0100000000feffffff02404b4c000000000017a91481d74bcd380c05f791d1f4c81837565dec9b234a8799c4c3230100000016001439a460078122352e30e8b9520e16dd603f39395100000000010120404b4c000000000017a91481d74bcd380c05f791d1f4c81837565dec9b234a870104160014bd7c79cd76a5491f01115b81372cdc9b05cedb00220603b22d357d64aa0c10caffcdaeb22fca282b31f011c8c2c8c6d5e56a676d52c8031873c5da0a310000800100008000000080000000000100000000
============== OUTPUT SCOPES ===============
---------- OUTPUT 0 ---------------
# redeem script for this output, required for verification that this output is indeed change output
01 00
16 001470beb1e04a500940e9f3abaa66e1a49ac55b8f35 - redeem script for this output
# bip32 derivation. Key is the public key, value is the derivation (key: <len><0x02><pubkey>)
22 02 02a2fc8996c5262248b5daefc5a4d0cdcd00c13047d0cb13028136ea630d875a87
18 - length of derivation
  73c5da0a - fingerprint
  31000080 - 49'
  01000080 - 1'
  00000080 - 0'
  01000000 - 1
  00000000 - 0
00 - end of scope
----------- OUTPUT 1 ------------
00 - empty, we don't know anything about this output
```

# Signing PSBT

When signing PSBT we need to go through every input and calculate a hash for it. Depending on the type of input we need to use either legacy signing algorithm, or segwit.

## Segwit signing algorithm:

First, we can calculate a few hashes that can be reused between inputs:

```
# hash txid vout of all inputs concatenated
hash_prevouts = sha256(sha256(<txhash0><vout0><txhash1><vout1>...))
# hash sequences of all inputs concatenated
hash_sequence = sha256(sha256(<sequence0><sequence1>...))
# hash all outputs concatenated
hash_outputs = sha256(sha256(<amount0><scriptpubkey0><amount1><scriptpubkey1>))
```

In our case:
```
prevouts = 1cb6d64ebf95ca23e9d6267b925dbd18c3935f691a867f3b83aab8f8d745d85c 01000000 ea0d8d93e39b27e9c7fb76ddbc122ab2092630d7458933d35f296dbf0adaf0c7 00000000
sequences = fdffffff fdffffff
outputs = f6073d0000000000 17a914251dd11457a259c3ba47e5cca3717fe4214e029887
c0d8a70000000000 22002023570715e1ac360b097d32781d2d571f9c5d8a07daf47c627c1e1efb24cb5ac0
```

```
hash_prevouts = 33555b25a146e6a7c9ece37d2c2f73f340864fe3c3fa071470db685d3b83027e
hash_sequence = 957879fdce4d8ab885e32ff307d54e75884da52522cc53d3c4fdb60edb69a098
hash_outputs = e642b66847d70b33ce142851945e4210861f796398b171e91470df9aa1b3551a
```

Now let's sign input 0. We need to get two values from the input scope 0:
- Amount of the previous output - 10000000 sats
- Previous Script - either witness script (if multisig), or redeem script (if wrapped segwit), or witness_utxo.script_pubkey (if native segwit). In our case (wrapped segwit) we take redeem script `001438971f73930f6c141d977ac4fd4a727c854935b3`

If the script is single-sig segwit (like in our case), we need to convert it to legacy p2pkh script - we take pubkey hash from the script (`38971f73930f6c141d977ac4fd4a727c854935b3`) and insert it into legacy p2pkh script: `76a91438971f73930f6c141d977ac4fd4a727c854935b388ac`.

To get a hash for signing we need to hash the following things:
- tx version (`02000000`)
- hash_prevouts (`33555b25a146e6a7c9ece37d2c2f73f340864fe3c3fa071470db685d3b83027e`)
- hash_sequence (`957879fdce4d8ab885e32ff307d54e75884da52522cc53d3c4fdb60edb69a098`)
- prev tx hash and vout of our input (`1cb6d64ebf95ca23e9d6267b925dbd18c3935f691a867f3b83aab8f8d745d85c 01000000`)
- script that we got above with length (`1976a91438971f73930f6c141d977ac4fd4a727c854935b388ac`)
- value that we got above (`8096980000000000` = 10000000 sats)
- sequence of our input (`fdffffff`)
- hash_outputs (`e642b66847d70b33ce142851945e4210861f796398b171e91470df9aa1b3551a`)
- locktime (`d9000000`)
- sighash (SIGHASH_ALL in our case - `01000000`)

```
hash = sha256(sha256( 02000000 33555b25a146e6a7c9ece37d2c2f73f340864fe3c3fa071470db685d3b83027e 957879fdce4d8ab885e32ff307d54e75884da52522cc53d3c4fdb60edb69a098 1cb6d64ebf95ca23e9d6267b925dbd18c3935f691a867f3b83aab8f8d745d85c 01000000 1976a91438971f73930f6c141d977ac4fd4a727c854935b388ac 8096980000000000 fdffffff e642b66847d70b33ce142851945e4210861f796398b171e91470df9aa1b3551a d9000000 01000000 )) =
```

And the resulting hash is `7d56777c37679edbfbdc635c4e90f87e17676571f8f6311a431cf086c9030d74`.

Now, in order to sign this hash we need to derive the private key from the root key using derivation path `m/49'/1'/0'/0/0`:

```
root: xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu
derivation: m/49'/1'/0'/0/0
derived xprv: xprvA3xqazGezXcjYigcosBVV6C613TjcQSCzGkw2wsMx6Kn8LU1NcU2y2nVuZwv9afxiD1QGJMXXeKUUuQCTABDkeV2peoBfK7MEMxbPR3qobP
derived 32-byte secret: c9bdb49cfbaedca21c4b1f3a7803c34636b1d7dc55a717132443fc3f4c5867e8
corresponding public key: 03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f

DER-signature: 304402206bb98cc2682fb71a7ce2bc72033dae383b51318359c04f1cbcbceb2263d825a80220723513601ce9a43c3e26c64170ed610eed5370a269af8fea1d84dd283bc05186
```

Repeating the same process for all inputs we receive the following data:
```
Input 0:
pubkey: 03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f
signature: 304402206bb98cc2682fb71a7ce2bc72033dae383b51318359c04f1cbcbceb2263d825a80220723513601ce9a43c3e26c64170ed610eed5370a269af8fea1d84dd283bc05186

Input 1:
pubkey: 03b22d357d64aa0c10caffcdaeb22fca282b31f011c8c2c8c6d5e56a676d52c803
signature: 304402206a3fdc2759544f19d112c6186f530d790e5776abbc9263b98e2c554f0ff143cf022008482ed584455ffb0bc32b244998cc4f2d4a0a1c1ba9b9560a6d2129236e2c74
```

# Including signature to the PSBT

We need to include signatures to every input metadata of the psbt. To decrease the size of the transaction we could remove some fields, like non-witness utxo, but for now we will keep everything as it was and only include signatures.

Partial signatures are serialized with key `<02><pubkey>` and value `<der_signature><sighash>` - notice that signature also has a sighash byte at the end, `0x01` in case of SIGHASH_ALL (default sighash in Bitcoin).

```
# old input metadata
0100720200000001da9a4b82aad88017f24aa54442fdb68844c24341cd217ae11a482312f46253a30100000000feffffff0258e2de22010000001600144395a9a9e8d9a1bcd44b8f425b4a779cf3245773809698000000000017a914336caa13e08b96080a32b5d818d59b4ab3b367428700000000010120809698000000000017a914336caa13e08b96080a32b5d818d59b4ab3b3674287010416001438971f73930f6c141d977ac4fd4a727c854935b3220603a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f1873c5da0a3100008001000080000000800000000000000000
# key - <02>pubkey
220203a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f
# value - <der_signature><sighash>
47304402206bb98cc2682fb71a7ce2bc72033dae383b51318359c04f1cbcbceb2263d825a80220723513601ce9a43c3e26c64170ed610eed5370a269af8fea1d84dd283bc0518601
# end of input metadata
00
```

The same for second input:

```
# old input metadata
0100720200000001f0f3e667c77b47815006dacdb72bef07bdbe9a36fa1c62896c469cf324c0b8fe0100000000feffffff02404b4c000000000017a91481d74bcd380c05f791d1f4c81837565dec9b234a8799c4c3230100000016001439a460078122352e30e8b9520e16dd603f39395100000000010120404b4c000000000017a91481d74bcd380c05f791d1f4c81837565dec9b234a87
0104160014bd7c79cd76a5491f01115b81372cdc9b05cedb00220603b22d357d64aa0c10caffcdaeb22fca282b31f011c8c2c8c6d5e56a676d52c8031873c5da0a3100008001000080000000800000000001000000
# pubkey
220203b22d357d64aa0c10caffcdaeb22fca282b31f011c8c2c8c6d5e56a676d52c803
# signature
47304402206a3fdc2759544f19d112c6186f530d790e5776abbc9263b98e2c554f0ff143cf022008482ed584455ffb0bc32b244998cc4f2d4a0a1c1ba9b9560a6d2129236e2c7401
# end of input
00
```

These values can be added to input at any place, I added them at the end for simplicity

# Finalizing transaction

On the host side, when we receive a signed psbt, we need to extract a raw bitcoin transaction ready for broadcasting.

We start by taking a raw unsigned transaction from psbt:

```
02000000 - version, little-endian (version = 2)
---- inputs -----
02 - number of inputs
---- input 0 ----
1cb6d64ebf95ca23e9d6267b925dbd18c3935f691a867f3b83aab8f8d745d85c - previous tx hash (reversed txid of the transaction we are spending)
01000000 - prev vout, little-endian (vout = 1)
00 - scriptsig, empty because transaction is unsigned
fdffffff - sequence number, little endian
---- input 1 ----
ea0d8d93e39b27e9c7fb76ddbc122ab2092630d7458933d35f296dbf0adaf0c7 - prev tx hash
00000000 - prev vout
00 - scriptsig
fdffffff - sequence number
---- outputs -----
02 - 2 outputs
---- output 0 ----
f6073d0000000000 - amount, 8-byte little endian, 3999734 sats
17a914251dd11457a259c3ba47e5cca3717fe4214e029887 - scriptpubkey of the output, address - 2MvdUi5o3f2tnEFh9yGvta6FzptTZtkPJC8
---- output 1 ----
c0d8a70000000000 - amount, 11000000 sats
22002023570715e1ac360b097d32781d2d571f9c5d8a07daf47c627c1e1efb24cb5ac0 - scriptpubkey
----------------
d9000000 - locktime
```

We only need to change inputs, and in case of segwit transactions (our case) also add a segwit marker and witness data

For every input we need to:

- inject redeem script to scriptsig if it's not empty (yes in our case)
- if it's a segwit transaction - construct witness data (yes in our case)
- if it's a segwit transaction - add a segwit marker after the version

An easy way to detect if the transaction is segwit or not - to look at psbt inputs metadata. Normally it's enough to check if `witness_utxo` is not empty - this should work in the 99% of cases.

For more complete check any of the following should be true:
- witness_utxo for any input is not empty
- witness_script for any input is not empty
- redeem script starts with `00` and followed by 20 or 32-byte len-encoded string (`0014<pubkeyhash>` or `0020<scripthash>`)
- redeem script is empty but previous utxo scriptpubkey starts with `00` followed by 20 or 32-byte len-encoded string

Witness data for single-sig contains two elements - a signature and a pubkey:

```
# witness for input 0:
02 - number of items
# der-signature with sighash
47304402206bb98cc2682fb71a7ce2bc72033dae383b51318359c04f1cbcbceb2263d825a80220723513601ce9a43c3e26c64170ed610eed5370a269af8fea1d84dd283bc0518601
# public key
2103a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f

# witness for input 1:
02 - number of items
# signature
47304402206a3fdc2759544f19d112c6186f530d790e5776abbc9263b98e2c554f0ff143cf022008482ed584455ffb0bc32b244998cc4f2d4a0a1c1ba9b9560a6d2129236e2c7401
# pubkey
2103b22d357d64aa0c10caffcdaeb22fca282b31f011c8c2c8c6d5e56a676d52c803
```

Annotated transaction with injected witnesses, segwit marker and redeem script:

```
02000000 - version
0001 - segwit flag and marker
---- inputs -----
02 - number of inputs
---- input 0 ----
1cb6d64ebf95ca23e9d6267b925dbd18c3935f691a867f3b83aab8f8d745d85c - txid
01000000 - vout
1716001438971f73930f6c141d977ac4fd4a727c854935b3 - scriptsig (redeem script from psbt input 0)
fdffffff - sequence number
---- input 1 ----
ea0d8d93e39b27e9c7fb76ddbc122ab2092630d7458933d35f296dbf0adaf0c7 - txid
00000000 - vout
17160014bd7c79cd76a5491f01115b81372cdc9b05cedb00 - scriptsig (redeem script from psbt input 1)
fdffffff - sequence number
---- outputs ----
02 - number of outputs
---- output 0 ----
f6073d0000000000 - amount
17a914251dd11457a259c3ba47e5cca3717fe4214e029887 - scriptpubkey
---- output 1 ----
c0d8a70000000000 - amount
22002023570715e1ac360b097d32781d2d571f9c5d8a07daf47c627c1e1efb24cb5ac0 - scriptpubkey
---- witness data ----
---- witness for input 0 ---
0247304402206bb98cc2682fb71a7ce2bc72033dae383b51318359c04f1cbcbceb2263d825a80220723513601ce9a43c3e26c64170ed610eed5370a269af8fea1d84dd283bc05186012103a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f
---- witness for input 1 ----
0247304402206a3fdc2759544f19d112c6186f530d790e5776abbc9263b98e2c554f0ff143cf022008482ed584455ffb0bc32b244998cc4f2d4a0a1c1ba9b9560a6d2129236e2c74012103b22d357d64aa0c10caffcdaeb22fca282b31f011c8c2c8c6d5e56a676d52c803
---- locktime ---
d9000000
```

Final transaction ready for broadcast:

```
020000000001021cb6d64ebf95ca23e9d6267b925dbd18c3935f691a867f3b83aab8f8d745d85c010000001716001438971f73930f6c141d977ac4fd4a727c854935b3fdffffffea0d8d93e39b27e9c7fb76ddbc122ab2092630d7458933d35f296dbf0adaf0c70000000017160014bd7c79cd76a5491f01115b81372cdc9b05cedb00fdffffff02f6073d000000000017a914251dd11457a259c3ba47e5cca3717fe4214e029887c0d8a7000000000022002023570715e1ac360b097d32781d2d571f9c5d8a07daf47c627c1e1efb24cb5ac00247304402206bb98cc2682fb71a7ce2bc72033dae383b51318359c04f1cbcbceb2263d825a80220723513601ce9a43c3e26c64170ed610eed5370a269af8fea1d84dd283bc05186012103a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f0247304402206a3fdc2759544f19d112c6186f530d790e5776abbc9263b98e2c554f0ff143cf022008482ed584455ffb0bc32b244998cc4f2d4a0a1c1ba9b9560a6d2129236e2c74012103b22d357d64aa0c10caffcdaeb22fca282b31f011c8c2c8c6d5e56a676d52c803d9000000
```
