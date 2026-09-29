# Panasonic Lumix "UPD" firmware packages – format notes (FT5 / TS5 / TZ40 / TZ41)

Notes and a small parser for the firmware update packages of the 2013 Panasonic
compacts **DMC-FT5 / TS5** and **DMC-TZ40 / TZ41 (ZS30)**.

**Status: the container format is understood; the encryption is not broken.**
Nothing here decrypts a module, and there is no way (yet) to build a package the
camera would accept. What is documented is what could be established from the
public update files alone, plus a few negative results that may save others time.

> No firmware images, camera dumps or keys are included in this repository.
> Update files are copyrighted; get them from Panasonic or your own camera.

## Files analysed

| File | Size | CRC32 (see below) |
|---|---|---|
| FT5 V1.1 | 104 306 176 B (0x6379600) | OK |
| FT5 V1.4 | 104 306 176 B (0x6379600) | OK |
| TS5 V1.4 | identical to FT5 V1.4 (byte for byte) | OK |
| TZ40 V1.3 | 104 830 464 B (0x63F9600) | OK |
| TZ41 V1.3 | identical to TZ40 V1.3 (byte for byte) | OK |

## Usage

```
python3 lumix_upd.py info FT5__V14.bin [--check-hash] [--json]
python3 lumix_upd.py compare FT5__V11.bin FT5__V14.bin
python3 lumix_upd.py extract FT5__V14.bin out/        # modules exactly as stored
python3 lumix_upd.py romtxt2bin FT5F.TXT FT5F.bin     # service-mode ROM BACKUP text -> binary
```

Python 3, standard library only.

## Package layout

All integers are little-endian.

| Offset | Size | Meaning |
|---|---|---|
| 0x000 | 4 | magic `UPD\0` |
| 0x004 / 0x008 | 4 + 4 | both `0x200` (header size?) |
| 0x00C | 16 | model string (`FT5`, `TZ40`, ...) |
| 0x01C / 0x01E | 2 + 2 | firmware version, BCD, stored twice: `0x0110` = 1.10, `0x0140` = 1.40 |
| 0x020 | 4 | `4` (meaning unknown) |
| 0x024 | 4 | build stamp: bytes = minute, hour, day, month in BCD (year not stored). FT5 V1.1 = 04-08 17:51, FT5 V1.4 = 03-27 12:39, TZ40 V1.3 = 03-27 13:20 *(interpretation; it is consistent with related releases being built on the same day)* |
| 0x02C–0x038 | 4 × 4 | small constants (`3, 0, 3, 0x200`), meaning unknown |
| 0x03C | 4 | end of module data (`0x06379400` on FT5) |
| **0x040** | 4 | **CRC32 (zlib) of `file[0x200:]`** – plain integrity check, no secret involved |
| 0x200 | 32 | vendor tag `panasonic\0...` |
| 0x220 | 64 | random-looking block, different in every build, not a plain hash of anything tried (see below) |
| 0x260–0x29F | 64 | zeros |
| 0x2A0 | 0x40 | second header, same fields as the first up to 0x3C |
| 0x2E0 | 4 | data start (`0xC00`) |
| 0x2E4 | 4 | data length (= data end − data start) |
| 0x2E8 | 4 | number of modules (FT5: 26, TZ40: 27) |
| 0x2EC | n × 92 | module table |
| 0xC00 | … | module data, contiguous, in table order |
| end | 0x200 | trailing `0xFF` (not covered by the module table) |

### Module table entry (92 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 12 | name (NUL padded) |
| 12 | 4 | absolute file offset |
| 16 | 4 | size (bytes, includes the 0x200 head) |
| 20 | 4 | load address in the camera's address space |
| 24 | 4 | flags: `2` = stored in clear, `3` = encrypted |
| 28 | 32 | digest (SHA-256, see "Digest rule") |
| 60 | 16 | `param`: all zero when flags = 2, random-looking when flags = 3 |
| 76 | 16 | zeros |

**Quirk:** the table (26 × 92 bytes on FT5, 27 on TZ40) is longer than the room
before `data_start`, so its last entries are written *over the first bytes of the
first module* (`boot`), whose own 0x200-byte head is otherwise empty. A parser
must read the table with a fixed stride and not stop at 0xC00.

### FT5 V1.4 module map

| # | name | load addr | size | flags |
|---|---|---|---|---|
| 0 | boot | 0x0000000 | 0x8000 | 3 |
| 1 | program | 0x0080000 | 0x6D8800 | 3 |
| 2 | storage | 0x0820000 | 0 | 2 |
| 3 | postboot1 | 0x0820000 | 0x11F000 | 3 |
| 4 | postboot2 | 0x093F000 | 0x9C800 | 3 |
| 5 | postboot3 | 0x09DB800 | 0x800 | 3 |
| 6 | postboot4 | 0x09DC000 | 0x57800 | 3 |
| 7 | postboot5 | 0x0A33800 | 0xC4000 | 3 |
| 8 | post_spare | 0x0AF7800 | 0x28800 | 2 |
| 9 | armcode | 0x0B20000 | 0x400000 | 3 |
| 10 | eep_ow_a | 0x0F20000 | 0x2000 | 3 |
| 11 | eep_ow_b | 0x0F40000 | 0x2000 | 3 |
| 12 | eep_adj | 0x0F60000 | 0x3000 | 3 |
| 13 | eep_fix | 0x0F63000 | 0x5000 | 3 |
| 14 | history | 0x0F80000 | 0x20000 | 2 |
| 15 | opedata | 0x0FA0000 | 0x28000 | 3 |
| 16 | osdover | 0x0FE0000 | 0x540000 | 3 |
| 17 | osddata | 0x1520000 | 0x358000 | 3 |
| 18 | packfile | 0x1960000 | 0x580000 | 3 |
| 19 | ninsho_fc1 | 0x2080000 | 0x4000 | 2 |
| 20 | ninsho_fc2 | 0x20A0000 | 0x1C000 | 2 |
| 21 | avchd_info | 0x20C0000 | 0x4000 | 2 |
| 22 | eep_net_a | 0x20E0000 | 0x4000 | 3 |
| 23 | eep_net_b | 0x2100000 | 0x4000 | 3 |
| 24 | map | 0x2160000 | 0x4480000 | 3 |
| 25 | gps_assist | 0x66C0000 | 0x280000 | 2 |

(TZ40 has 27 modules; it adds `map_prog`, 0x80000 bytes at 0x6640000.)

## The module "head" (first 0x200 bytes)

Every module starts with a 0x200-byte head. Its content varies:

* `armcode` (0xFF), `opedata` and `eep_net_a` (0x00): empty. Their encrypted data starts at +0x200.
* `boot`: empty, except for the module table written over it (see the quirk above).
* all other modules, including the clear ones (`history`, `post_spare`, ...): 512
  random-looking bytes that **change completely between builds even when the module
  content and its digest are identical**. Purpose unknown. Could be a per-module
  signature or a per-build value; the fact that four encrypted modules have an empty
  head argues against a mandatory per-module signature.

## Digest rule (verified)

For the modules stored in clear (flags = 2), the table digest reproduces as

```
digest = SHA-256( B * 0x200  ||  module[0x200:] )        with B = 0x00 or 0xFF
```

i.e. it covers the module with a **blank head** (0x00 or 0xFF, not the random head
stored in the file) followed by the payload. Verified for `history`, `post_spare`
and `avchd_info`; `storage` (size 0) carries the SHA-256 of the empty string. It does
not reproduce with this rule for `ninsho_fc1`, `ninsho_fc2` and `gps_assist` (not investigated further).

Consequence: for an encrypted module, `SHA-256(blank head || decrypted payload)` should
equal the table digest (the rule holds for the blank encrypted modules `eep_net_a/b`,
see below), so a correct decryption can be **verified** without any external reference.

## Encryption – what is known

* flags = 2: data in clear, `param` is all zeros. flags = 3: high-entropy data, `param`
  is different for every module.
* Payloads appear to be encrypted from module offset 0x200 (where the head is empty it stays empty, e.g. `eep_net_a`).
* **A new `param` and a new ciphertext are generated for every module in every build**,
  even when the plaintext is unchanged. Between FT5 V1.1 and V1.4, ten encrypted modules have
  identical plaintext (same digest); their ciphertexts agree on about 0.3–0.5 % of bytes,
  which is what random data gives (1/256 = 0.39 %). Inside one package, `eep_ow_a`/`eep_ow_b`
  and `eep_net_a`/`eep_net_b` have the same digest but different `param` and unrelated
  ciphertext. Hence no keystream reuse / two-time-pad to exploit.
* No repeated 16-byte blocks inside any encrypted module: not ECB with a fixed key.
* FT5 V1.4 and TS5 V1.4 are the same file, as are TZ40 V1.3 and TZ41 V1.3. Same plaintext
  encrypted for FT5 and TZ40 (e.g. `map`, `opedata`) gives unrelated ciphertexts as well.

### Known-plaintext test vectors

`eep_net_a` and `eep_net_b` decrypt to **all 0xFF** (the digest equals
`SHA-256(0xFF * 0x4000)` = `0fbba07a…0dee`). The payload is therefore known
plaintext. First 32 bytes of the ciphertext (module offset 0x200) and the `param`:

| package | module | param | ciphertext[0:32] |
|---|---|---|---|
| FT5 V1.4 | eep_net_a | `0b62fed73580b2701f49e8d8d7e10af0` | `c74de834f15946b42727815d743f909aaf1699d8f6ef9d0db083b3caa89912d2` |
| FT5 V1.4 | eep_net_b | `d381f7207752ca0d551ebc1b89f51a14` | `8aa3be544fa759ef6d4a5e00bf4dc0869f13eb8c34e22df211ba70d53f9552a2` |
| FT5 V1.1 | eep_net_a | `429f4e5532c83a8ba69afd9005c61612` | `70d422a6403436327300a54feec0382b47d560080293af0b3019cf6dad725a02` |
| FT5 V1.1 | eep_net_b | `7bdfb5305f52b2121a7b5b6348ec338f` | `c5719469cf85254939d3a714ab7f103e0f9ca1989e8f541d68b69f5e81080604` |

Negative results on these vectors (so nobody repeats them):

* AES-128/192/256 in ECB, CBC, CTR (big/little-endian counter), CFB/OFB first block,
  with keys taken from `param`, from the 64-byte block at 0x220, or from MD5 / SHA-1 /
  SHA-256 / SHA-512 of those (16/24/32-byte truncations, repeated forms) and IVs of
  zero, `param` or part of the 64-byte block: about 16 000 combinations, **no match**.
* The keystream (ciphertext XOR 0xFF, 15 872 bytes) is statistically ideal: flat byte
  histogram, linear complexity ≈ n/2 (Berlekamp–Massey on 4096 bits), no periodicity,
  no relation to `param`.

The cipher therefore looks like a modern one keyed with a secret that is not in the package.

## Not known

* Algorithm, mode, and where the key comes from (device ROM/fuses, boot code, ...).
  The `boot` module is encrypted too.
* How `param` is used (IV, nonce, salt, wrapped key).
* What the 512-byte heads and the 64-byte block at 0x220 are. Sizes would fit RSA/ECDSA
  signatures, but that is speculation. If they are signatures over the module table or
  contents, a modified package cannot be made acceptable without patching the verifier.
* Digest scope for `ninsho_fc1`, `ninsho_fc2`, `gps_assist`.
* Whether the camera accepts downgrades (untested; do not flash old images blindly).

## Hardware and service-mode notes (from Panasonic's public FT5/TS5 service manual, DSC1304010CE)

* Main processor "Venus Engine" IC6001 (package-on-package with 512 Mbit SDRAM);
  1 Gbit NAND IC6005 holds firmware and the "EEPROM area"; Wi-Fi module on SDIO,
  separate NFC IC, GPS module. No debug port or test pad is documented.
* A hidden service menu (temporary cancellation of INITIAL SETTINGS) offers
  ROM BACKUP, SELF TEST and GPS DISP. ROM BACKUP writes `<Model>U.TXT` (user set-up
  data) and `<Model>F.TXT` (electrical adjustment data) to the card. For the FT5 the
  dumps are 8 192 and 32 768 bytes; the sizes match `eep_ow_a/b` (0x2000) and
  `eep_adj + eep_fix` (0x3000 + 0x5000). The mapping is a hypothesis based on sizes.
* **`F` dumps contain the camera's serial number and calibration; `U` dumps may
  contain Wi-Fi/user settings. Do not publish them.**
* Panasonic's PC service tool ("DIAS") is distributed to authorised service partners only.
* Opening the camera requires an air-leak test with special equipment afterwards
  (the camera is rated IPX8).

## Ideas that could still work (untested)

* Read-only USB enumeration in normal, PictBridge and service modes to look for a
  service protocol.
* Hardware access (debug pads, NAND dump) on a spare unit, or a memory dump of the
  decrypted image while running. The known-plaintext vectors and the digest rule
  above provide a way to validate any key or decryption hypothesis.

## License

Code: MIT. Text: CC BY 4.0. Panasonic and Lumix are trademarks of their owners;
this project is not affiliated with Panasonic.
