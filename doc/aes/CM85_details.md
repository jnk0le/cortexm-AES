# cortex-m85



## base impl

### CM85_1T

scalar only, potential for opt

similarly to CM7, dtcm access pattern can be timed by DMA

### CM85_held4T

usues diffused 4 T tables

not optimized yet

shiftrows by MVE is not very efficient

## perfomance

| Cipher function  | RA8D1 - CM85_1T  | RA8D1 - CM85_held4T |
|------------------|------------------|------------------|
| `setEncKey<128>` | 120 |  |
| `setEncKey<192>` |  |  |
| `setEncKey<256>` |  |  |
| `encrypt<128>`   | 263 |  |
| `encrypt<192>`   | 313 |  |
| `encrypt<256>`   | 363 |  |
| `setDecKey<128>` |  |  |
| `setDecKey<192>` |  |  |
| `setDecKey<256>` |  |  |
| `decrypt<128>`   |  |  |
| `decrypt<192>`   |  |  |
| `decrypt<256>`   |  |  |

## specific function size

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------|
| `CM85_1T_AES128_keyschedule_enc` | 124 | 24 | uses Te2 table |
| `CM85_1T_AES_encrypt` | 446 | 40 | uses Te2 table |