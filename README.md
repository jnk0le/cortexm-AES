# cortexm AES

FIPS 197 compliant software AES implementation optimized for real world cortex-m microcontrollers.

## build

Repository root directory is expected to be the only include path.

If repo is added as eclipse linked folder the root folder has to be added to ASM, C and CPP include paths (-I)
(proj preporties -> C++ build -> settings)

Includes also have to start from root (e.g. `#include <aes/cipher.hpp>`)

No cmake yet.

## notes
- Do not use ECB cipher mode for any serious encryption.
- Do not blindly trust in timming constantness of LUT based ciphers since it depends on many factors that are 
unknown or just implementation defined like section placement or pipeline suprises (you need to verify it, especially where is `.data` 
section).
- LUT tables have to be placed in deterministic memory section, usally TCMs and non-waitstated SRAMs (by default it lands in .data section)
- FLASH memory is unsafe even on simplest cortex m0(+) as there might be a prefetcher with a few entry cache (like stm32f0/l0)
- None of the currently available implementations protects against power/EMI analysis or glitch attacks.
- do not use cortex-m3 and cortex-m4 implementations on cortex-m7 since it is slower and will introduce timming leaks.
- Unrolled ciphers might perform slower than looped versions due to (usually LRU) cache pressure and flash waitstates. (like STM32F4 with 1K ART cache and up to 8WS)
- input/output buffers might have to be word aligned due to use of ldm,stm,ldrd and strd instructions.
- for optimization gimmicks refer to [pipeline cycle test repo](https://github.com/jnk0le/random/tree/master/pipeline%20cycle%20test)
- included unit tests don't cover timming leaks (performance difference on different runs may not be a data dependent ones)  
- asm functions (and CM*.h headers) can be extracted and used as C only code, but that may require extra boilerplate code (structures etc.)

## cryptoanalysis 

some of the cryptoanalysis works/papers, that tested one or more of the provided implementations.

https://webthesis.biblio.polito.it/secure/26870/1/tesi.pdf - (CM3_1T on cortex-m4 @ [1871e94](https://github.com/jnk0le/cortexm-AES/commit/1871e94c9c74e95fbfd9a5682b14941878ca2adb))

## base implementations

- [cortex-m0/m0+](doc/aes/CM0_details.md)
- [cortex-m3/m4](doc/aes/CM3_CM4_details.md)
- [cortex-m7](doc/aes/CM7_details.md)
- [QingKe v2 (ch32v003)](doc/aes/QKv2_details.md)

## modes implementations


### generic

#### CBC_GENERIC

#### CTR32_GENERIC

### cortex-m0/m0+

### cortex-m3/m4

### cortex-m7

#### CTR32_CM7_1T

Implements counter mode caching. Do not use if IV/counter is secret as it will lead to a timming leak of a single byte, every 256 aligned counter steps.

Preloads input data in case it's in SDRAM or QSPI memory.

#### CTR32_CM7_1T_unrolled

unrolled version of CTR32_CM7_1T, doesn't preload input data except first cacheline.

#### performance (in cycles per byte)

| Mode cipher function       | STM32H7 - CM7_1T |
|----------------------------|------------------|
| CTR32<128>                 | 15.21            |
| CTR32<192>                 | 18.58            |
| CTR32<256>                 | 21.96            |
| CTR32_unrolled<128>        | 14.46            |
| CTR32_unrolled<192>        | 17.70            |
| CTR32_unrolled<256>        | 20.95            |

#### specific function sizes

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------|
| `CM7_1T_AES_CTR32_enc` | 860 | 72 (+1 arg passed on stack) | uses Te2 table |
| `CM7_1T_AES128_CTR32_enc_unrolled` | | | uses Te2 table |
| `CM7_1T_AES192_CTR32_enc_unrolled` | | | uses Te2 table |
| `CM7_1T_AES256_CTR32_enc_unrolled` | | | uses Te2 table |
