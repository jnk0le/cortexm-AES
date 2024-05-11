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

https://webthesis.biblio.polito.it/secure/26870/1/tesi.pdf - (CM3_1T on cortex-m4)

## base implementations


### cortex-m0/m0+

#### CM0_sBOX

Uses simple sbox with parallel mixcolumns

Forward mixcolumns is done as (and according to [this](http://www.wseas.us/e-library/conferences/2009/moscow/AIC/AIC44.pdf)
or [this](https://www.researchgate.net/publication/221002183_Efficient_AES_implementations_for_ARM_based_platforms) 
paper, can be done with 3 xor + 3 rotations or 4 xor + 2 rotations as used here):

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
|------------------|------------------------------|-------------------------------------|------------------------------|-------------------------------|
| `setEncKey<128>` | 399/415 | (sBOX) |  |  |
| `setEncKey<192>` | 375/389 | (sBOX) |  |  |
| `setEncKey<256>` | 568/586 | (sBOX) |  |  |
| `encrypt<128>`   | 1666/1680 | 1587/1600 |  |  |
| `encrypt<192>`   | 2000/2016 | 1905/1920 |  |  |
| `encrypt<256>`   | 2334/2352 | 2223/2240 |  |  |
| `setDecKey<128>` | 0 | 0 | 0 | 0 |
| `setDecKey<192>` | 0 | 0 | 0 | 0 |
| `setDecKey<256>` | 0 | 0 | 0 | 0 |
| `decrypt<128>`   | 2567/2580 | 2387/2400 |  |  |
| `decrypt<192>`   | 3099/3114 | 2879/2894 |  |  |
| `decrypt<256>`   | 3631/3648 | 3371/3388 |  |  |

STM32F0 is cortex-m0 (prefetch enabled for 1ws, no prefetch leads to ~45% performance degradation)

STM32L0 is cortex-m0+ (prefetch enabled for 1ws)

#### specific function sizes

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------| 
| `CM0_sBOX_AES128_keyschedule_enc` | 80 | 16 | uses sbox table |
| `CM0_sBOX_AES192_keyschedule_enc` | 88 | 20(24) | uses sbox table |
| `CM0_sBOX_AES256_keyschedule_enc` | 164 | 32 | uses sbox table |
| `CM0_sBOX_AES_encrypt` | 508 | 40 | uses sbox table |
| `CM0_sBOX_AES_decrypt` | 712 | 40 | uses inv_sbox table |
| `CM0_FASTMULsBOX_AES_encrypt` | 480 | 36(40) | uses sbox table, requires single cycle multiplier |
| `CM0_FASTMULsBOX_AES_decrypt` | 672 | 40 | uses inv_sbox table, requires single cycle multiplier |

code sizes include pc-rel constants and their padding

extra 4 bytes on stack comes from aligning stack to 8 bytes on ISR entry.

### cortex-m3/m4

32 bit LDR opcodes are aligned to 4 byte boundaries (instructions not data) to prevent weird 
undocumented "feature" of cortex-m3/4 that prevents some pipelining of neighbouring loads.

LUT tables have to be placed in non cached and non waitstated SRAM memory with 32bit 
wide access, that is not crossing different memory domains (eg. AHB slaves).

#### CM3_1T

cortex m3 and cortex m4 optimized implementation.
Uses a single T table per enc/dec cipher and additional inv_sbox for final round in decryption.

Originally based on "Peter Schwabe and Ko Stoffelen" AES implementation available 
[here](https://github.com/Ko-/aes-armcortexm).

#### CM3_1T_unrolled

Same as CM3_1T but uses unrollend enc/dec functions

#### CM3_1T_deconly

Same as CM3_1T. Uses sbox table in key expansions instead of Te2 to reduce pressure on SRAM for decryption only use cases

#### CM3_1T_unrolled_deconly

Same as CM3_1T_deconly but uses unrollend enc/dec functions

#### CM3_sBOX


#### CM4_DSPsBOX

Utilizes simple sbox and dsp instructions to perform constant time, quad (gf)multiplications in mixcolumns stage.

Forward mixcolumns is done as (and according to [this](http://www.wseas.us/e-library/conferences/2009/moscow/AIC/AIC44.pdf)
or [this](https://www.researchgate.net/publication/221002183_Efficient_AES_implementations_for_ARM_based_platforms) 
paper, can be done with 4 xor + 2 rotations or 3 xor + 3 rotations as used here):

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
	uadd8 r6, r4, r4 // quad lsl #1
	eor r8, r6, #0x1b1b1b1b
	sel r4, r8, r6 // if uadd carried then take reduced byte
```


#### performance

| Cipher function  | STM32F1 (0ws/2ws) - CM3_1T | STM32F1 (0ws/2ws) - CM3_sBOX | STM32F4 (0ws/5ws) - CM3_1T | STM32F4 - CM4_DSPsBOX |
|------------------|----------------------------|------------------------------|----------------------------|-----------------------|
| `setEncKey<128>`        | 302/358  |  | 302 | 302 |
| `setEncKey<192>`        | 276/311  |  | 276 | 277 |
| `setEncKey<256>`        | 378/485  |  | 379 | 381 |
| `encrypt<128>`          | 646/884  |  | 645 | 852 |
| `encrypt<192>`          | 766/1049 |  | 765 | 1020 |
| `encrypt<256>`          | 886/1217 |  | 887 | 1188 |
| `encrypt_unrolled<128>` | 603/836  |   | 602/779 | - |
| `encrypt_unrolled<192>` | 713/990  |   | 712/922 | - |
| `encrypt_unrolled<256>` | 823/1148 |   | 822/1067 | - |
| `setDecKey<128>`        | 813/1101 | 0 | 811 | 0 |
| `setDecKey<192>`        | 987/1341 | 0 | 987 | 0 |
| `setDecKey<256>`        | 1163/1580 | 0 | 1164 | 0 |
| `decrypt<128>`          | 651/901  |   | 650 | 1249 |
| `decrypt<192>`          | 771/1072 |   | 770 | 1505 |
| `decrypt<256>`          | 891/1242 |   | 892 | 1759 |
| `decrypt_unrolled<128>` | 606/847  |   | 604/785 | - |
| `decrypt_unrolled<192>` | 716/1003 |   | 714/928 | - |
| `decrypt_unrolled<256>` | 826/1159 |   | 824/1073 | - |

results assume that input, expanded round key and stack lie in the same memory block (e.g. SRAM1 vs SRAM2 and CCM on f407)

#### specific function sizes

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------|
| `CM3_1T_AES128_keyschedule_enc` | 100 | 24 | uses Te2 table |
| `CM3_1T_AES192_keyschedule_enc` | 100 | 32 | uses Te2 table |
| `CM3_1T_AES256_keyschedule_enc` | 178 | 44(48) | uses Te2 table |
| `CM3_1T_AES_keyschedule_dec` | 92 | 12(16) | uses Te2 and Td2 table |
| `CM3_1T_AES_keyschedule_dec_noTe` | 86 | 12(16) | uses sbox and Td2 table |
| `CM3_1T_AES_encrypt` | 434 | 44(48) | uses Te2 table |
| `CM3_1T_AES_decrypt` | 450 | 44(48) | uses Td2 and inv_sbox table |
| `CM3_1T_AES128_encrypt_unrolled` | 1978 | 40 | uses Te2 table |
| `CM3_1T_AES128_decrypt_unrolled` | 1996 | 40 | uses Td2 and inv_sbox table |
| `CM3_1T_AES192_encrypt_unrolled` | 2362 | 40 | uses Te2 table |
| `CM3_1T_AES192_decrypt_unrolled` | 2380 | 40 | uses Td2 and inv_sbox table |
| `CM3_1T_AES256_encrypt_unrolled` | 2746 | 40 | uses Te2 table |
| `CM3_1T_AES256_decrypt_unrolled` | 2764 | 40 | uses Td2 and inv_sbox table |
| `CM3_sBOX_AES128_keyschedule_enc` | 100 | 24 | uses sbox table |
| `CM3_sBOX_AES192_keyschedule_enc` | 100 | 32 | uses sbox table |
| `CM3_sBOX_AES256_keyschedule_enc` | 178 | 44(48) | uses sbox table |
| `CM4_DSPsBOX_AES_encrypt` | 494 | 44(48) | uses sbox table |
| `CM4_DSPsBOX_AES_decrypt` | 630 | 44(48) | uses inv_sbox table |

extra 4 bytes on stack comes from aligning stack to 8 bytes on ISR entry.

### cortex-m7

optimized to avoid dual issue of data dependent loads which cause stalls when accessing DTCM 
(implemented as 2 separate single ported SRAMs) on both even or odd words. 

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
The timing effects of simultaneous access to DTCM memory by core and DMA/AHBS are yet unknown.
(there was some changes in r1p0 revision: "Improved handling of simultaneous AHBS and software activity relating to the same TCM", details are of course Proprietary&Confidential)



#### CM7_1T

cortex m7 optimized implementation.
Uses a single T table per enc/dec cipher and additional inv_sbox for final round in decryption.

#### CM7_1T_deconly

Same as CM7_1T. Uses sbox table in key expansions instead of Te2 to reduce pressure on SRAM for decryption only use cases

#### CM7_DSPsBOX

Utilizes simple sbox and dsp instructions to perform constant time, quad (gf)multiplications in mixcolumns stage.

Forward mixcolumns is done as (and according to [this](http://www.wseas.us/e-library/conferences/2009/moscow/AIC/AIC44.pdf)
or [this](https://www.researchgate.net/publication/221002183_Efficient_AES_implementations_for_ARM_based_platforms) 
paper, can be done with 4 xor + 2 rotations or 3 xor + 3 rotations as used here):

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
	uadd8 r6, r4, r4 // quad lsl #1
	eor r8, r6, #0x1b1b1b1b
	sel r4, r8, r6 // if uadd carried then take reduced byte
```

#### performance

| Cipher function  | STM32H7 - CM7_1T | STM32H7 - CM7_DSPsBOX |
|------------------|------------------|-----------------------|
| `setEncKey<128>` | 139 | 139 |
| `setEncKey<192>` | 129 | 129 |
| `setEncKey<256>` | 178 | 178 |
| `encrypt<128>`   | 292 | 400 |
| `encrypt<192>`   | 346 | 478 |
| `encrypt<256>`   | 400 | 556 |
| `setDecKey<128>` | 357 | 357 |
| `setDecKey<192>` | 433 | 433 |
| `setDecKey<256>` | 509 | 509 |
| `decrypt<128>`   | 293 | (1T) |
| `decrypt<192>`   | 347 | (1T) |
| `decrypt<256>`   | 401 | (1T) |

cm7 runtime cycles are biased a bit by caller or around caller code (numbers are from current ecb unit test,
no other code in loop)

#### specific function sizes

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------|
| `CM7_1T_AES128_keyschedule_enc` | 132 | 24 | uses Te2 table |
| `CM7_1T_AES192_keyschedule_enc` | 124 | 32 | uses Te2 table |
| `CM7_1T_AES256_keyschedule_enc` | 208 | 36(40) | uses Te2 table |
| `CM7_1T_AES_keyschedule_dec` | 180 | 32 | uses Te2 and Td2 table |
| `CM7_1T_AES_keyschedule_dec_noTe` | 180 | 32 | uses sbox and Td2 table |
| `CM7_1T_AES_encrypt` | 408 | 40 | uses Te2 table |
| `CM7_1T_AES_decrypt` | 400 | 40 | uses Td2 and inv_sbox table |
| `CM7_sBOX_AES128_keyschedule_enc` | 132 | 24 | uses sbox table |
| `CM7_sBOX_AES192_keyschedule_enc` | 124 | 32 | uses sbox table |
| `CM7_sBOX_AES256_keyschedule_enc` | 208 | 36(40) | uses sbox table |
| `CM7_DSPsBOX_AES_encrypt` | 466 | 40 | uses sbox table |

extra 4 bytes on stack comes from aligning stack to 8 bytes on ISR entry.

### "QingKeV2" (ch32v003)

ilp32e
xw extension
no multiplier

#### QKv2_sBOX

implemented similarly to cm0

#### denser??

#### performance

| Cipher function  | ch32v003 (0ws/1ws) - QKv2sBOX |
|------------------|------------------|
| `setEncKey<128>` | 461/478 |
| `setEncKey<192>` |  |
| `setEncKey<256>` |  |
| `encrypt<128>`   | 1853/2115 |
| `encrypt<192>`   |  |
| `encrypt<256>`   |  |
| `setDecKey<128>` |  |
| `setDecKey<192>` |  |
| `setDecKey<256>` |  |
| `decrypt<128>`   |  |
| `decrypt<192>`   |  |
| `decrypt<256>`   |  |

#### specific function sizes

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------|
| `QKv2_AES128_keyschedule_enc` | 82 | 4 | uses sbox |
| `QKv2_sBOX_AES_encrypt` | 738 | 16 | uses sbox |

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
