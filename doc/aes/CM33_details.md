# cortex-m33





## base impl

### CM33_1T



## perfomance

| Cipher function  |  RP2350 - CM33_1T |
|------------------|-------------------|
| `setEncKey<128>` | 271 |
| `setEncKey<256>` | 307 |
| `encrypt<128>`    | 574 |
| `encrypt<256>`    | 790 |
| `setDecKey<128>` | |
| `setDecKey<256>` | |
| `decrypt<128>`    | 576 |
| `decrypt<256>`    | 792 |

## specific function size

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------|
| `CM33_1T_AES128_keyschedule_enc` | 94 | 16 | uses Te2 table |
| `CM33_1T_AES192_keyschedule_enc` | | | uses Te2 table |
| `CM33_1T_AES256_keyschedule_enc` | 162 | 32 | uses Te2 table |
| `CM33_1T_AES_keyschedule_dec` | | | uses Te2 and Td2 table |
| `CM33_1T_AES_keyschedule_dec_noTe` | | | uses sbox and Td2 table |
| `CM33_1T_AES_encrypt` | 400 | 28(32) | uses Te2 table |
| `CM33_1T_AES_decrypt` | 408 | 28(32)| uses Td2 and inv_sbox table |

extra 4 bytes on stack comes from aligning stack to 8 bytes on ISR entry.