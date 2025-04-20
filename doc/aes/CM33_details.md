# cortex-m33



## base impl

### CM33_1T



## perfomance

| Cipher function  |  ??? - CM33_1T |
|------------------|-------------------|
| `setEncKey<128>` | |
| `setEncKey<256>` | |
| `encrypt<128>`    | |
| `encrypt<256>`    | |
| `setDecKey<128>` | |
| `setDecKey<256>` | |
| `decrypt<128>`    | |
| `decrypt<256>`    | |

## specific function size

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------|
| `CM3_1T_AES128_keyschedule_enc` | | | uses Te2 table |
| `CM3_1T_AES192_keyschedule_enc` | | | uses Te2 table |
| `CM3_1T_AES256_keyschedule_enc` | | | uses Te2 table |
| `CM3_1T_AES_keyschedule_dec` | | | uses Te2 and Td2 table |
| `CM3_1T_AES_keyschedule_dec_noTe` | | | uses sbox and Td2 table |
| `CM3_1T_AES_encrypt` | | | uses Te2 table |
| `CM3_1T_AES_decrypt` | | | uses Td2 and inv_sbox table |

extra 4 bytes on stack comes from aligning stack to 8 bytes on ISR entry.