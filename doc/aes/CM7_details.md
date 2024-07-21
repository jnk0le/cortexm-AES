# cortex-m7

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

The AHBS interface has [configurable priorty](https://developer.arm.com/documentation/ddi0489/f/system-control/register-descriptions/ahb-slave-control-register). 
By default AHBS interface has the lowest priority which means that DMA transfers through this interface can be timed
to discover access pattern to DTCM banks.
(there was also some changes in r1p0 revision: "Improved handling of simultaneous AHBS and 
software activity relating to the same TCM", details are of course Proprietary&Confidential)

## base impl

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

## perfomance

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

## specific function size

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
