## modes implementations

(this part needs rework, will be replaced later)

### generic

#### CBC_GENERIC

#### CTR32_GENERIC

### cortex-m0/m0+

### cortex-m3/m4

#### CTR32_CM3_1T

Implements counter mode caching. Do not use if IV/counter is secret as it will lead to a timming leak of a single byte, every 256 aligned counter steps.

#### CTR32_CM3_1T_unrolled

unrolled version of CTR32_CM3_1T

#### performance (in cycles per byte)

| Mode cipher function       | STM32F1 (0ws/2ws) - CM3_1T | STM32F4 (0ws/5ws) - CM3_1T |
|----------------------------|------------------|------------------|
| CBC_GENERIC<>              |                  |                  |
| CTR32_GENERIC<>            |                  |                  |
| CTR32<128>                 | 32.09/43.79      | 32.09            |
| CTR32<256>                 | 46.59/63.79      | 46.59            |
| CTR32_unrolled<128>        | 30.59/41.60      | 30.59/38.48      |
| CTR32_unrolled<256>        | 44.34/59.98      | 44.34/55.73      |

results assume that input, expanded round key and stack lie in the same memory block (e.g. SRAM1 vs SRAM2 and CCM on f407)

#### specific function sizes

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------|
| `CM3_1T_AES_CTR32_enc` | 862 | 68(72) (+1 arg passed on stack) | uses Te2 table |
| `CM3_1T_AES128_CTR32_enc_unrolled` | 1996 | 64 | uses Te2 table |
| `CM3_1T_AES192_CTR32_enc_unrolled` | 2366 | 64 | uses Te2 table |
| `CM3_1T_AES256_CTR32_enc_unrolled` | 2734 | 64 | uses Te2 table |

extra 4 bytes on stack comes from aligning stack to 8 bytes on ISR entry.

### cortex-m7

#### CTR32_CM7_1T

Implements counter mode caching. Do not use if IV/counter is secret as it will lead to a timming leak of a single byte, every 256 aligned counter steps.

Preloads input data in case it's in SDRAM or QSPI memory.

#### CTR32_CM7_1T_unrolled

unrolled version of CTR32_CM7_1T, doesn't preload input data except first cacheline.

#### performance (in cycles per byte)

| Mode cipher function       | STM32H7 - CM7_1T |
|----------------------------|------------------|
| CBC_GENERIC<>              |                  |
| CTR32_GENERIC<>            |                  |
| CTR32<128>                 | 15.21            |
| CTR32<256>                 | 21.96            |
| CTR32_unrolled<128>        | 14.46            |
| CTR32_unrolled<256>        | 20.95            |

#### specific function sizes

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------|
| `CM7_1T_AES_CTR32_enc` | 860 | 72 (+1 arg passed on stack) | uses Te2 table |
| `CM7_1T_AES128_CTR32_enc_unrolled` | | | uses Te2 table |
| `CM7_1T_AES192_CTR32_enc_unrolled` | | | uses Te2 table |
| `CM7_1T_AES256_CTR32_enc_unrolled` | | | uses Te2 table |
