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
- None of the currently available implementations protects against power/EMI analysis attacks.
- do not use cortex-m3 and cortex-m4 implementations on cortex-m7 since it is slower and will introduce timming leaks.
- Unrolled ciphers might perform slower than looped versions due to (usually LRU) cache pressure and flash waitstates. (like STM32F4 with 1K ART cache and up to 8WS)
- input/output buffers might have to be word aligned due to use of ldm,stm,ldrd and strd instructions.
- for optimization gimmicks refer to [pipeline cycle test repo](https://github.com/jnk0le/random/tree/master/pipeline%20cycle%20test) (ignore old (CM7) comments inside code here - they are likely outdated)
- included unit tests don't cover timming leaks (performance difference on different runs may not be a data dependent ones)  
- asm functions (and CM*.h headers) can be extracted and used as C only code, but that may require extra boilerplate code (structures etc.)

## base implementations


### cortex-m0/m0+

#### CM0_sBOX

Uses simple sbox with parallel mixcolumns

Forward mixcolumns is done as (and according to [this](http://www.wseas.us/e-library/conferences/2009/moscow/AIC/AIC44.pdf) or [this](https://www.researchgate.net/publication/221002183_Efficient_AES_implementations_for_ARM_based_platforms) paper, can be done with 3 xor + 3 rotations or 4 xor + 2 rotations as used here):

```
tmp = s0 ^ s1 ^ s2 ^ s3
s0` ^= tmp ^ gmul2(s0^s1) // s1^s2^s3^gmul2(s0^s1)
s1` ^= tmp ^ gmul2(s1^s2) // s0^s2^s3^gmul2(s1^s2)
s2` ^= tmp ^ gmul2(s2^s3) // s0^s1^s3^gmul2(s2^s3)
S3` ^= tmp ^ gmul2(s3^s0) // s0^s1^s2^gmul2(s3^s0)
```

Inverse mixcolums is implemented as:

```
S{2} = gmul2(S{1})
S{4} = gmul2(S{2})
S{8} = gmul2(S{4})

S{9} = S{8} ^ S{1}
S{b} = S{9} ^ S{2}
S{d} = S{9} ^ S{4}
S{e} = S{8} ^ S{4} ^ S{2}

out = S{e} ^ ror8(S{b}) ^ ror16(S{d}) ^ ror24(S{9})
	
s0{e}^s1{b}^s2{d}^s3{9} | s1{e}^s2{b}^s3{d}^s0{9} | s2{e}^s3{b}^s0{d}^s1{9} | s3{e}^s0{b}^s1{d}^s2{9}
```

`gmul2()` is implementend as:

```
mask = in & 0x80808080;
out = ((in & 0x7f7f7f7f) << 1) ^ ((mask - (mask >> 7)) & 0x1b1b1b1b);
```

#### CM0_FASTMULsBOX

Faster than CM0sBOX only when running on core with single cycle multiplier (used for predicated reduction in mixcolumns multiplication)

Implemented similarly to CM0sBOX but with `gmul2()` implementend as:

```
out = ((in & 0x7f7f7f7f) << 1) ^ (((in & 0x80808080) >> 7)) * 0x1b);

// or equivalent sequence to perform shifts first in order to avoid extra moves
out = ((in << 1) & 0xfefefefe) ^ (((in >> 7) & 0x01010101) * 0x1b)
```

#### performance

| Cipher function  | STM32F0 (0ws/1ws) - CM0_sBOX | STM32F0 (0ws/1ws) - CM0_FASTMULsBOX | STM32L0 (0ws/1ws) - CM0_sBOX | STM32L0 (0ws/1ws) - CM0_FASTMULsBOX |
|----------------------|---|---|---|---|
| `setEncKey<128>` | 417/431 | (sBOX) |  |  |
| `setEncKey<192>` | 386/398 | (sBOX) |  |  |
| `setEncKey<256>` | 598/610 | (sBOX) |  |  |
| `encrypt<128>`    | 1666/1680 | 1587/1600 |  |  |
| `encrypt<192>`    | 2000/2016 | 1905/1920 |  |  |
| `encrypt<256>`    | 2334/2352 | 2223/2240 |  |  |
| `setDecKey<128>` | 0 | 0 | 0 | 0 |
| `setDecKey<192>` | 0 | 0 | 0 | 0 |
| `setDecKey<256>` | 0 | 0 | 0 | 0 |
| `decrypt<128>`    | 2567/2580 | 2387/2400 |  |  |
| `decrypt<192>`    | 3099/3114 | 2879/2894 |  |  |
| `decrypt<256>`    | 3631/3648 | 3371/3388 |  |  |

STM32F0 is cortex-m0 (prefetch enabled for 1ws, no prefetch leads to ~45% performance degradation)

STM32L0 is cortex-m0+ (prefetch enabled for 1ws)

#### specific function sizes

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------| 
| `CM0_sBOX_AES_128_keyschedule_enc` | 74 | 16 | uses sbox table |
| `CM0_sBOX_AES_192_keyschedule_enc` | 86 | 20(24) | uses sbox table |
| `CM0_sBOX_AES_256_keyschedule_enc` | 172 | 28(32) | uses sbox table |
| `CM0_sBOX_AES_encrypt` | 508 | 40 | uses sbox table |
| `CM0_sBOX_AES_decrypt` | 712 | 40 | uses inv_sbox table |
| `CM0_FASTMULsBOX_AES_encrypt` | 480 | 36(40) | uses sbox table, requires single cycle multiplier |
| `CM0_FASTMULsBOX_AES_decrypt` | 672 | 40 | uses inv_sbox table, requires single cycle multiplier |

code sizes include pc-rel constants and their padding

extra 4 bytes on stack comes from aligning stack to 8 bytes on ISR entry.

### cortex-m3/m4

#### CM3_1T


can be used on cortex-m3 and cortex m4





#### CM3_1T_unrolled

Same as CM3_1T but uses unrollend enc/dec functions

#### CM3_1T_deconly

Same as CM3_1T. Uses sbox table in key expansions instead of Te2 to reduce pressure on SRAM for decryption only use cases

#### CM3_1T_unrolled_deconly

Same as CM3_1T_deconly but uses unrollend enc/dec functions

#### CM3_sBOX

TBD

#### CM4_DSPsBOX




#### performance

| Cipher function  | STM32F1 (0ws/2ws) - CM3_1T | STM32F1 (0ws/2ws) - CM3_sBOX | STM32F4 (0ws/5ws) - CM3_1T | STM32F4 - CM4_DSPsBOX |
|--------------------------------|---------|-------|-------|-------|
| `setEncKey<128>`          | 302/358  |  | 302 | 302 |
| `setEncKey<192>`          | 276/311  |  | 276 | 277 |
| `setEncKey<256>`          | 378/485  |  | 379 | 381 |
| `encrypt<128>`             | 646/884  |  | 645 | 852 |
| `encrypt<192>`             | 766/1049 |  | 765 | 1020 |
| `encrypt<256>`             | 886/1217 |  | 887 | 1188 |
| `encrypt_unrolled<128>` | 603/836  |   | 602/779 | - |
| `encrypt_unrolled<192>` | 713/990  |   | 712/922 | - |
| `encrypt_unrolled<256>` | 823/1148 |   | 822/1067 | - |
| `setDecKey<128>`          | 813/1101 | 0 | 811 | 0 |
| `setDecKey<192>`          | 987/1341 | 0 | 987 | 0 |
| `setDecKey<256>`          | 1163/1580 | 0 | 1164 | 0 |
| `decrypt<128>`             | 651/901  |   | 650 | 1249 |
| `decrypt<192>`             | 771/1072 |   | 770 | 1505 |
| `decrypt<256>`             | 891/1242 |   | 892 | 1759 |
| `decrypt_unrolled<128>` | 606/847  |   | 604/785 | - |
| `decrypt_unrolled<192>` | 716/1003 |   | 714/928 | - |
| `decrypt_unrolled<256>` | 826/1159 |   | 824/1073 | - |

results assume that input, expanded round key and stack lie in the same memory block (e.g. SRAM1 vs SRAM2 and CCM on f407)

#### specific function sizes

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------|
| `CM3_1T_AES_128_keyschedule_enc` | 100 | 24 | uses Te2 table |
| `CM3_1T_AES_192_keyschedule_enc` | 100 | 32 | uses Te2 table |
| `CM3_1T_AES_256_keyschedule_enc` | 178 | 44(48) | uses Te2 table |
| `CM3_1T_AES_keyschedule_dec` | 92 | 12(16) | uses Te2 and Td2 table |
| `CM3_1T_AES_keyschedule_dec_noTe` | 86 | 12(16) | uses sbox and Td2 table |
| `CM3_1T_AES_encrypt` | 434 | 44(48) | uses Te2 table |
| `CM3_1T_AES_decrypt` | 450 | 44(48) | uses Td2 and inv_sbox table |
| `CM3_1T_AES_128_encrypt_unrolled` | 1978 | 40 | uses Te2 table |
| `CM3_1T_AES_128_decrypt_unrolled` | 1996 | 40 | uses Td2 and inv_sbox table |
| `CM3_1T_AES_192_encrypt_unrolled` | 2362 | 40 | uses Te2 table |
| `CM3_1T_AES_192_decrypt_unrolled` | 2380 | 40 | uses Td2 and inv_sbox table |
| `CM3_1T_AES_256_encrypt_unrolled` | 2746 | 40 | uses Te2 table |
| `CM3_1T_AES_256_decrypt_unrolled` | 2764 | 40 | uses Td2 and inv_sbox table |
| `CM3_sBOX_AES_128_keyschedule_enc` | 100 | 24 | uses sbox table |
| `CM3_sBOX_AES_192_keyschedule_enc` | 100 | 32 | uses sbox table |
| `CM3_sBOX_AES_256_keyschedule_enc` | 178 | 44(48) | uses sbox table |
| `CM4_DSPsBOX_AES_encrypt` | 494 | 44(48) | uses sbox table |
| `CM4_DSPsBOX_AES_decrypt` | 630 | 44(48) | uses inv_sbox table |

extra 4 bytes on stack comes from aligning stack to 8 bytes on ISR entry.

### cortex-m7

TBD


#### performance

| Cipher function  | STM32H7 - CM7_1T | STM32H7 - CM7_DSPsBOX |
|--------------------------------|---------|-------|
| `setEncKey<128>`          | 141 | 141 |
| `setEncKey<192>`          | 131 | 131 |

#### specific function sizes

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------|
| `CM7_1T_AES_128_keyschedule_enc` | 132 | 24 | uses Te2 table |
| `CM7_1T_AES_192_keyschedule_enc` | 124 | 32 | uses Te2 table |
| `CM7_1T_AES_256_keyschedule_enc` |  |  | uses Te2 table |
| `CM7_sBOX_AES_128_keyschedule_enc` | 132 | 24 | uses sbox table |
| `CM7_sBOX_AES_192_keyschedule_enc` | 124 | 32 | uses sbox table |
| `CM7_sBOX_AES_256_keyschedule_enc` |  |  | uses sbox table |

### cortex-m55

no hardware available yet, TBD

### RI5CY

RI5CY as in GAP8, not the later CV32E40P that is more constrained.

TBD

## modes implementations

### cortex-m0/m0+

### cortex-m3/m4

### cortex-m7

### cortex-m55

### RI5CY


## implementations (this part will be replaced later)


### CM3_1T

cortex m3 and cortex m4 optimized implementation.
Uses a single T table per enc/dec cipher and additional inv_sbox for final round in decryption.

Originally based on "Peter Schwabe and Ko Stoffelen" AES implementation available [here](https://github.com/Ko-/aes-armcortexm).

32 bit LDR opcodes are aligned to 4 byte boundaries to prevent weird undocumented "feature" of cortex-m3/4 that prevents some pipelining of neighbouring loads.
As well as other architecture specific optimizations.

LUT tables have to be placed in non cached and non waitstated SRAM memory with 32bit wide access, that is not crossing different memory domains (eg. AHB slaves).
FLASH memory simply cannot be used since vendors usually implements some kind of cache, wide prefetch buffers, and waitstates that will anyway make cipher slower than boxless one.

### CM7_1T

cortex m7 optimized implementation.
Uses a single T table per enc/dec cipher and additional inv_sbox for final round in decryption.

Based on cortex m3/4 one, with carefully reordered instructions for cortex-m7 pipeline, to increase IPC and avoid data dependent 
stalls when accessing 2x32 bit DTCM (separate single ported SRAMs) on even/odd words. 

The timmming issue can be visualized by following snippet (immediate vs register offset doesn't matter):

```
	tick = DWT->CYCCNT;
	asm volatile(""
			"movw r12, #:lower16:AES_Te0 \n"
			"movt r12, #:upper16:AES_Te0 \n"
			"ldr r0, [r12, #0] \n"
			"ldr r1, [r12, #8] \n"
			"ldr r2, [r12, #16] \n"
			"ldr r3, [r12, #24] \n"
			""::: "r0","r1","r2","r3","r12");
	tick = DWT->CYCCNT - tick - 1;

	printf("4 even loads, cycles: %lu\n", tick);

	tick = DWT->CYCCNT;
	asm volatile(""
			"movw r12, #:lower16:AES_Te0 \n"
			"movt r12, #:upper16:AES_Te0 \n"
			"ldr r0, [r12, #0] \n"
			"ldr r1, [r12, #4] \n"
			"ldr r2, [r12, #8] \n"
			"ldr r3, [r12, #12] \n"
			""::: "r0","r1","r2","r3","r12");
	tick = DWT->CYCCNT - tick - 1;

	printf("4 linear loads, cycles: %lu\n", tick);
	printf("This is why any two data dependent LDRs cannot be placed next to each other\n");
```

Only DTCM memory can be used for LUT tables, since everything else is cached through AXI bus.
The timing effects of simultaneous access to DTCM memory by core and DMA/AHBS are yet unknown. (there was some changes in r1p0 revision: "Improved handling of simultaneous AHBS and software activity relating to the same TCM", details are of course Proprietary&Confidential)

### XXX_DSPsBOX

Utilizes dsp instructions to perform constant time, quad (gf)multiplications in mixcolumns stage.
MixCloums stage is parallelized according to [this](http://www.wseas.us/e-library/conferences/2009/moscow/AIC/AIC44.pdf) or [this](https://www.researchgate.net/publication/221002183_Efficient_AES_implementations_for_ARM_based_platforms) paper, InvMixColums is done through more straightforward representation.

## Base ciphers performance (in cycles per block, some numbers are outdated)

| Cipher function     | STM32F1 (0ws/2ws) - CM3_1T | STM32F4 (0ws/7ws) - CM3_1T | STM32F4 (0ws/7ws) - CM4_DSPsBOX | STM32H7 - CM7_1T | STM32H7 - CM7_DSPsBOX |
|---------------------|----------------------------|----------------------------|---------------------------------|------------------|-----------------------|
| `setEncKey<128>`    |    |   |  | 157* | 157* |
| `setEncKey<192>`    |    |    |  | 140* | 140* |
| `setEncKey<256>`    |    |   |  | 227* | 227* |
| `encrypt<128>`      |    | |  | 302 | 411 |
| `encrypt<192>`      |    | |  | 358 | 491 |
| `encrypt<256>`      |   |  |  | 414 | 571 |
| `enc_unrolled<128>` |    | | - | 281 | - |
| `enc_unrolled<192>` |    | | - | 333 | - |
| `enc_unrolled<256>` |  | | - | 385 | - |
| `setDecKey<128>`    |   | |  | 412* | (1T) |
| `setDecKey<192>`    |   | |  | 500* | (1T) |
| `setDecKey<256>`    |  | |  | 588* | (1T) |
| `decrypt<128>`      |    | |  | 304 | (1T) |
| `decrypt<192>`      |   | |  | 360 | (1T) |
| `decrypt<256>`      |     | |  | 416 | (1T) |
| `dec_unrolled<128>` |    | | - | 282 | - |
| `dec_unrolled<192>` |   | | - | 334 | - |
| `dec_unrolled<256>` |   | | - | 386 | - |

Results are averaged over 1024 runs + one ommited (instruction) cache train run.
`setDecKey<>` counts cycles required to perform equivalent inverse cipher transformation on expanded encryption key.
`*` pipeline performance not fixed yet
`**` Cortex-M7 results may differ depending on the code around the caller (`encrypt<128>` should have 299 retired "uop pairs", goes up by e.g. 9 cycles if unrolled code is also compiled in)

### XXX_1T_CTR

Implements counter mode caching. Do not use if IV/counter is secret as it will lead to a timming leak of a single byte, every 256 aligned counter steps.

## Cipher modes performance (in cycles per byte, some numbers are outdated)

| Cipher function            | STM32F1 (0ws/2ws) - CM3_1T | STM32F4 (0ws/7ws) - CM3_1T | STM32H7 - CM7_1T |
|----------------------------|-----------------------------|-----------------------------|------------------|
| CBC_GENERIC<128> enc(+dec) |      |                 | 19.83(+0.24)      |
| CBC_GENERIC<192> enc(+dec) |     |                 | 23.39(+0.24)      |
| CBC_GENERIC<256> enc(+dec) |     |                  | 26.88(+0.24)      |
| CTR_GENERIC<128>           |                  |                        | 19.50            |
| CTR_GENERIC<192>           |                  |                        | 23.00            |
| CTR_GENERIC<256>           |                  |                        | 26.50            |
| CTR<128>                   | 32.97                 | 32.91                  | 15.64           |
| CTR<192>                   | 40.47                | 40.41                  | 19.14           |
| CTR<256>                   | 47.97                 | 47.91                  | 22.64           |
| CTR_unrolled<128>          |                  | 30.72                 | 14.52           |
| CTR_unrolled<192>          |                  | 37.59                 | 17.77           |
| CTR_unrolled<256>          |                  | 44.47                 | 21.02           |

F407 results assume that input, expanded round key and stack lie in the same memory block (e.g. SRAM1 vs SRAM2 and CCM on f407)
