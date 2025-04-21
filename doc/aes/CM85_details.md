# cortex-m85


Similarly to CM7, all lookup tables must be placed in DTCM memory.

## base impl

### CM85_1T

scalar only

Uses a single T table per enc/dec cipher and additional inv_sbox for final round in decryption.

similarly to CM7, dtcm access pattern can still be timed by DMA

### CM85_d4T

Vectorized, shiftrows and T boxing goes through scalar due to lacking performance of scatter/gather. 
(unpipelineable with other vector insns)

uses diffused 4 T tables, which is fully resistant to bank timming attacks (within DTCM).

(only encryption is available at the moment, no keyschedules yet)

## perfomance

| Cipher function  | RA8D1 - CM85_1T  | RA8D1 - CM85_d4T |
|------------------|------------------|------------------|
| `setEncKey<128>` | 120 |  |
| `setEncKey<256>` |  |  |
| `encrypt<128>`   | 263 | 273 |
| `encrypt<256>`   | 363 | 377 |
| `setDecKey<128>` |  |  |
| `setDecKey<256>` |  |  |
| `decrypt<128>`   |  |  |
| `decrypt<256>`   |  |  |

## specific function size

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------|
| `CM85_1T_AES128_keyschedule_enc` | 124 | 24 | uses Te2 table |
| `CM85_1T_AES_encrypt` | 446 | 40 | uses Te2 table |
| `CM85_d4T_AES_encrypt` | 342 | 56 | uses d4Te table, sensitive (partially processed in final round) data visits stack |