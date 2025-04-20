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
- Do not use ECB cipher mode for any serious encryption. It's provided for building proper modes.
- Do not blindly trust in timming constantness of LUT based ciphers since it depends on many factors that are 
unknown or just implementation defined like section placement or pipeline suprises (you need to verify it, especially where is `.data` 
section).
- LUT tables have to be placed in deterministic memory section, usally TCMs and non-waitstated SRAMs (by default it lands in .data section)
- FLASH memory is unsafe even on simplest cortex m0(+) as there might be a prefetcher with a few entry cache (like stm32f0/l0).
However in some cases it's still possible when running at reduced clock, with flash configured to 0ws and explicitly disabled prefetch.
- None of the currently available implementations protects against power/EMI analysis or glitch attacks.
- using implementations on wrong microarchitecture might introduce timming leaks (e.g. CM3_1T run on CM7).
- Unrolled implementations might perform slower than looped versions due to (usually LRU) cache pressure and flash waitstates. (like STM32F4 with 1K ART cache and up to 8WS)
- input/output buffers might have to be word aligned due to use of ldm,stm,ldrd and strd instructions.
- for optimization gimmicks refer to [pipeline cycle test repo](https://github.com/jnk0le/random/tree/master/pipeline%20cycle%20test)
- included unit tests don't cover timming leaks (performance difference on different runs may not be a data dependent ones,
there are special tools like dudect for that)

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

- [old](doc/aes/modes_old.md)