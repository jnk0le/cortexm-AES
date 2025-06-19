# cortexm AES

Collection of software AES implementations optimized for real world microcontrollers.

## build

Repository root directory is expected to be the only include path.

If repo is added as eclipse linked folder the root folder has to be added to ASM, C and CPP include paths (-I)
(proj preporties -> C++ build -> settings)

Includes also have to start from root (e.g. `#include <aes/cipher.hpp>`)

No cmake yet.

## notes

- asm functions (and CM*.h headers) can be extracted and used as C only code, but that may require extra boilerplate code (structures etc.)
- C++ API doesn't use exceptions nor dynamic memory allocation
- Do not use base implementations (ECB mode) for any serious encryption. It's provided for building proper modes.
- Do not blindly trust in timming constantness of LUT based ciphers since it depends on many factors that are 
unknown or just implementation defined like section placement or pipeline suprises (you need to verify it, especially where is `.data` 
section).
- LUT tables have to be placed in deterministic memory section, usally TCMs and non-waitstated SRAMs (by default it lands in `.data` section)
- FLASH memory is unsafe even on simplest cortex m0(+) as there might be a prefetcher with a few entry cache (like stm32f0/l0).
However in some cases it's still possible when running at reduced clock, with flash configured to 0ws and explicitly disabled prefetch.
- None of the currently available implementations protects against power/EMI analysis or glitch attacks.
- using implementations on wrong microarchitecture might introduce timming leaks (e.g. CM3_1T run on CM7).
- Unrolled implementations might perform slower than looped versions due to (usually LRU) cache pressure and flash waitstates. (like STM32F4 with 1K ART cache and up to 8WS)
- for optimization gimmicks refer to [pipeline cycle test repo](https://github.com/jnk0le/random/tree/master/pipeline%20cycle%20test)
- included unit tests don't cover timming leaks (performance difference on different runs may not be a data dependent ones,
there are special tools like [dudect](https://eprint.iacr.org/2016/1123.pdf) for that)

## cryptoanalysis 

some of the cryptoanalysis works/papers, that tested one or more of the provided implementations.

https://webthesis.biblio.polito.it/secure/26870/1/tesi.pdf - (CM3_1T on cortex-m4 @ [1871e94](https://github.com/jnk0le/cortexm-AES/tree/1871e94c9c74e95fbfd9a5682b14941878ca2adb))

## base implementations

- [cortex-m0/m0+](doc/aes/CM0_details.md)
- [cortex-m3/m4](doc/aes/CM3_CM4_details.md)
- [cortex-m7](doc/aes/CM7_details.md)
- [cortex-m33](doc/aes/CM33_details.md)
- [cortex-m85](doc/aes/CM85_details.md)
- [QingKe v2 (ch32v003)](doc/aes/QKv2_details.md)

## modes implementations

Available implementations, by C++ wrapper, consist of the following modes: 

### `CBC_PKCS7`

Handles PKCS7 padding, unpadded encryption can be achieved by not calling `xxxAppendFinalize()` function.

- `CBC_GENERIC`

### `CTR_32`

SP 800-38A compliant, with 32 bit (big endian) counter.
Can be used to build more common AEAD modes.

All implementations internally require nonce placed before expanded roundkey.

```
typedef struct {
    uint8_t nonce[16];
    uint8_t rk[(n+1)*16];
} ctx;
```

- `CTR32_GENERIC`
- target specific implementations ?????


### `GCM`, `GCM_FUSED`

SP 800-38D compliant, GCM mode. Typially used in TLS.

All implementations are currently based on CTR_32 class. (there will be fused ctr+ghash encryption which will require some redesign)

Table based implementations are implemented accoding to:
https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
The GCM context needs to be placed in uncached SRAM/TCM memory (required by M tables only).

The FULL-table implementations are not recommended as the 4 bit version doesn't improve speed enough
and 8 bit one requires unrealistic amount of uncached memory.

The `BEAR_CT{32}` implementations come from bearSSL package and are constant time with
single cycle multipliers (use CT32 for cortex-m0 and cortex-m3).
See https://www.bearssl.org/constanttime.html#ghash-for-gcm for details.


- `GHASH_GENERIC_BEAR_CT`
- `GHASH_GENERIC_BEAR_CT32`
- `GHASH_GENERIC_SHOUP_M4`
- `GHASH_GENERIC_SHOUP_M8`
- `GHASH_GENERIC_FULL_M4`
- `GHASH_GENERIC_FULL_M8` (not yet)
- target specific implementations ?????

#### memory reqirements

| bytes of memory used by | per session | constants |
|-------------------------|-------------|-----------|
| `BEAR_*`          | 64 + AES roundkey | 0 + AES   |
| `SHOUP_M4`       | 304 + AES roundkey | 64 + AES  |
| `SHOUP_M8`       | 4144 + AES roundkey | 1024 + AES |
| `FULL_M4`        | 8240 + AES roundkey | 0 + AES    |
| `FULL_M8`        |  + AES roundkey | 0 + AES    |




### target specific implementations:


- [old, will be replaced later](doc/aes/modes_old.md)