# cortex-m33

cortex m33 optimized implementations.


## base impl

### CM33_1T

Uses a single T table per enc/dec cipher and additional inv_sbox for final round in decryption.

On RP2350 only SRAM8 and SRAM9 can be used for lookups to be free from bank timming.
(unstriped alias of main blocks is not available)

### CM33_d4T

Uses the diffused 4 T tables, a bit slower than 1T due to extra setup and register pressure.

Fully resistant to bank timming attacks on 2 or 4 banked (by word
striping) SRAM memories (e.g. SRAM0-7 in rp2350)

currently only encryption is available

## perfomance

| Cipher function  | RP2350 - CM33_1T | RP2350 - CM33_d4T |
|------------------|------------------|-------------------|
| `setEncKey<128>` | 271 | |
| `setEncKey<256>` | 307 | |
| `encrypt<128>`    | 574 | 595 |
| `encrypt<256>`    | 790 | 815 |
| `setDecKey<128>` | | |
| `setDecKey<256>` | | |
| `decrypt<128>`    | 576 | |
| `decrypt<256>`    | 792 | |

## specific function size

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------|
| `CM33_1T_AES128_keyschedule_enc` | 94 | 16 | uses Te2 table |
| `CM33_1T_AES192_keyschedule_enc` | | | uses Te2 table |
| `CM33_1T_AES256_keyschedule_enc` | 162 | 32 | uses Te2 table |
| `CM33_1T_AES_keyschedule_dec` | | | uses Te2 and Td2 table |
| `CM33_1T_AES_keyschedule_dec_noTe` | | | uses sbox and Td2 table |
| `CM33_1T_AES_encrypt` | 400 | 28(32) | uses Te2 table |
| `CM33_1T_AES_decrypt` | 408 | 28(32) | uses Td2 and inv_sbox table |
| `CM33_d4T_AES_encrypt` | 426 | 44(48) | uses d4Te table |

extra 4 bytes on stack comes from aligning stack to 8 bytes on ISR entry.
