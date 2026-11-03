# Ratify Protocol key storage record

The Swift and Kotlin SDKs store a key in one documented, implementation-neutral
record. Any implementation can read and write it from this description alone.
The format is the same on every platform; only the protection around it differs.

## Layout

All integers are unsigned and big-endian.

```
record = "RFYK"            4 bytes, ASCII magic
         version           u8, = 1
         record_type       u8
         key_id_len        u16, = 64
         key_id            key_id_len bytes, the v2 key ID (64 lowercase hex characters)
         field_count       u8
         field*            field_count times

field  = tag u8 || len u16 || value (len bytes)
```

The **header** is every byte before `field_count`: `"RFYK" || version ||
record_type || key_id_len || key_id`.

## Record types

Each type has exactly these fields, once each, in this order.

| Type | Meaning | Fields |
|------|---------|--------|
| `0x01` | Software key | `0x01` ed25519_seed (32), `0x02` mldsa65_seed (32) |
| `0x02` | Apple Secure Enclave hybrid | `0x01` ed25519_seed (32), `0x03` mldsa65_public (1952), `0x04` se_data_representation (1 or more) |
| `0x03` | Android split custody | `0x02` mldsa65_seed (32), `0x05` ed25519_public (32), `0x06` keystore_alias (1 or more) |

`ed25519_seed` is the 32-byte Ed25519 private seed and `mldsa65_seed` is the
32-byte FIPS 204 ML-DSA-65 key generation seed. `se_data_representation` is the
Secure Enclave key's opaque, device-bound data representation: a type `0x02`
record cannot move to another device, by design.

## Reading a record

A reader refuses the record as `malformed` when the magic, version, record type
or any tag is unknown, a tag is missing or repeated, a length is wrong, the key
ID is not 64 lowercase hex characters, or bytes remain after the last field. It
then derives the public key from the record's key material and refuses the
record as `key_id_mismatch` if its key ID is not the recorded one. Future
versions are read-old, write-new: a reader never rewrites a record silently.

## Where records are kept

- **iOS and macOS**: a Keychain generic-password item with service
  `com.ratifyprotocol.v2.key`, account = the key ID, data = the record,
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, never synchronizable, with an
  optional access group.
- **Android**: the file `files/ratify/keys/<key_id>.key` in app-private
  storage, holding `header || nonce (12) || ciphertext || tag (16)`. The
  ciphertext is AES-256-GCM of the record's bytes after the header, under the
  non-exportable Android Keystore key `ratify.v2.wrap.<key_id>` (StrongBox when
  the device has it, optionally requiring user authentication), with the header
  as associated data. A reader checks that the header names the key it was
  asked for before decrypting, and refuses a file that fails authentication.

## Test vector

The software key derived from the `root` seeds of `testvectors/v2/keys.json`
(Ed25519 seed `4141414141414141414141414141414141414141414141414141414141414141`, ML-DSA-65 seed `c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1`)
has key ID `f1f0d864b26519693951ba784d29ae70c09bea932842e0667dccd41ba8b8ba71` and this type `0x01` record (143 bytes):

```
5246594b0101004066316630643836346232363531393639333935316261373834643239616537306330396265613933323834326530363637646363643431626138623862613731020100204141414141414141414141414141414141414141414141414141414141414141020020c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1
```
