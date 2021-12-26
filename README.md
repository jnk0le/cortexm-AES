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

// or modified sequence to perform shifts first in order to to avoid extra moves
out = ((in << 1) & 0xfefefefe) ^ (((in >> 7) & 0x01010101) * 0x1b)
```

#### performance

| Cipher function  | STM32F0 (0ws/1ws) - CM0_sBOX | STM32F0 (0ws/1ws) - CM0_FASTMULsBOX | STM32L0 (0ws/1ws) - CM0_sBOX | STM32L0 (0ws/1ws) - CM0_FASTMULsBOX |
|----------------------|---|---|---|---|
| `setEncKey<128>` | 417/431 | 417/431 |  |  |
| `setEncKey<192>` | 386/398 | 386/398 |  |  |
| `setEncKey<256>` | 598/610 | 598/610 |  |  |
| `encrypt<128>`    | 1666/1680 | 1587/1600 |  |  |
| `encrypt<192>`    | 2000/2016 | 1905/1920 |  |  |
| `encrypt<256>`    | 2334/2352 | 2223/2240 |  |  |
| `setDecKey<128>` | 0 | 0 | 0 | 0 |
| `setDecKey<192>` | 0 | 0 | 0 | 0 |
| `setDecKey<256>` | 0 | 0 | 0 | 0 |
| `decrypt<128>`    | 2675/2688 | 2387/2400 |  |  | 
| `decrypt<192>`    | 3231/3246 | 2879/2894 |  |  | 
| `decrypt<256>`    | 3787/3804 | 3371/3388 |  |  | 

STM32F0 is cortex-m0 (prefetch enabled for 1ws, no prefetch leads to ~45% performance degradation)

STM32L0 is cortex-m0+ (prefetch enabled for 1ws)

#### specific function sizes

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------| 
| `CM0_sBOX_AES_128_keyschedule_enc` | 74 | 16 | uses sbox table |
| `CM0_sBOX_AES_192_keyschedule_enc` | 86 | 20(24) | uses sbox table |
| `CM0_sBOX_AES_256_keyschedule_enc` | 172 | 28(32) | uses sbox table |
| `CM0_sBOX_AES_encrypt` | 508 | 40 | uses sbox table |
| `CM0_sBOX_AES_decrypt` | 736 | 40 | uses inv_sbox table |
| `CM0_FASTMULsBOX_AES_encrypt` | 480 | 36(40) | uses sbox table, requires single cycle multiplier |
| `CM0_FASTMULsBOX_AES_decrypt` | 672 | 40 | uses inv_sbox table, requires single cycle multiplier |

code sizes include pc-rel constants and their padding

extra 4 bytes on stack comes from aligning stack to 8 bytes on ISR entry.

### cortex-m3/m4

TBD

### cortex-m7

TBD


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

## Base ciphers performance (in cycles per block)

| Cipher function     | STM32F1 (0ws/2ws) - CM3_1T | STM32F4 (0ws/7ws) - CM3_1T | STM32F4 (0ws/7ws) - CM4_DSPsBOX | STM32H7 - CM7_1T | STM32H7 - CM7_DSPsBOX |
|---------------------|----------------------------|----------------------------|---------------------------------|------------------|-----------------------|
| `setEncKey<128>`    | 302/355   | 305      | 305 | 157* | 157* |
| `setEncKey<192>`    | 278/348   | 281      | 281 | 140* | 140* |
| `setEncKey<256>`    | 402/516   | 434      | 434 | 227* | 227* |
| `encrypt<128>`      | 657/843   | 669      | 884 | 302 | 411 |
| `encrypt<192>`      | 779/998   | 793      | 1056 | 358 | 491 |
| `encrypt<256>`      | 901/1155  | 917      | 1228 | 414 | 571 |
| `enc_unrolled<128>` | 604/834   | 604/1029 | - | 281 | - |
| `enc_unrolled<192>` | 714/993   | 714/1221 | - | 333 | - |
| `enc_unrolled<256>` | 824/1148  | 824/1413 | - | 385 | - |
| `setDecKey<128>`    | 813/1102  | 816      | 0 | 412* | (1T) |
| `setDecKey<192>`    | 989/1342  | 992      | 0 | 500* | (1T) |
| `setDecKey<256>`    | 1165/1585 | 1168     | 0 | 588* | (1T) |
| `decrypt<128>`      | 652/898   | 673      | 1272 | 304 | (1T) |
| `decrypt<192>`      | 772/1071  | 797      | 1530 | 360 | (1T) |
| `decrypt<256>`      | 892/1240  | 921      | 1788 | 416 | (1T) |
| `dec_unrolled<128>` | 607/836   | 609/1032 | - | 282 | - |
| `dec_unrolled<192>` | 717/995   | 719/1224 | - | 334 | - |
| `dec_unrolled<256>` | 827/1150  | 829/1416 | - | 386 | - |

Results are averaged over 1024 runs + one ommited (instruction) cache train run.
`setDecKey<>` counts cycles required to perform equivalent inverse cipher transformation on expanded encryption key.
`*` pipeline performance not fixed yet
`**` Cortex-M7 results may differ depending on the code around the caller (`encrypt<128>` should have 299 retired "uop pairs", goes up by e.g. 9 cycles if unrolled code is also compiled in)

### XXX_1T_CTR

Implements counter mode caching. Do not use if IV/counter is secret as it will lead to a timming leak of a single byte, every 256 aligned counter steps.

## Cipher modes performance (in cycles per byte)

| Cipher function            | STM32F1 (0ws/2ws) - CM3_1T | STM32F4 (0ws/7ws) - CM3_1T | STM32H7 - CM7_1T |
|----------------------------|-----------------------------|-----------------------------|------------------|
| CBC_GENERIC<128> enc(+dec) | 43.08(-0.3)/55.28(+3.5)     | 43.96(+0.37)                | 19.83(+0.24)      |
| CBC_GENERIC<192> enc(+dec) | 50.71(-0.3)/65.03(+4.37)    | 51.64(+0.44)                | 23.39(+0.24)      |
| CBC_GENERIC<256> enc(+dec) | 58.33(-0.3)/74.97(+5.06)    | 59.39(+0.3)                 | 26.88(+0.24)      |
| CTR_GENERIC<128>           | 42.32/54.81                 | 43.06                       | 19.50            |
| CTR_GENERIC<192>           | 49.95/64.69                 | 50.81                       | 23.00            |
| CTR_GENERIC<256>           | 57.57/74.75                 | 58.56                       | 26.50            |
| CTR<128>                   | 33.72/44.23*                 | 34.53*                       | 15.64*           |
| CTR<192>                   | 41.35/54.23*                 | 42.28*                       | 19.14*           |
| CTR<256>                   | 48.97/64.23*                 | 50.03*                       | 22.64*           |
| CTR_unrolled<128>          | 31.03/43.54*                 | 31.41/53.68*                 | 14.52           |
| CTR_unrolled<192>          | 37.91/53.35*                 | 38.28/65.67*                 | 17.77           |
| CTR_unrolled<256>          | 44.78/63.04*                 | 45.16/77.68*                 | 21.02           |

`*` minor perf/consistency
