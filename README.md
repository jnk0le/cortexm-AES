# cortexm AES

FIPS 197 compliant software AES implementation optimized for real world cortex-m3/4/7 microcontrollers.


## notes
- Do not use ECB cipher mode for anything more than 16 bytes of plaintext data per key.
- Do not blindly trust in timming constantness of LUT based implementations since it depends on many factors that are 
unknown or just implementation defined like section placement (you need to verify it, especially before use in production).
- None of the currently available implementations protects against power/EMI analysis attacks.
- do not use CM34_1T implementation on cortex-m7 since it is slower and will introduce timming leaks.
- Unrolled ciphers might perform slower than looped versions due to cache pressure and flash waitstates. (like STM32F4 with 1K ART cache and up to 8WS) 
- input/output buffers have to be word aligned due to use of ldm,stm and strd instructions.

## implementations

### CM34_1T

Uses a single T table per enc/dec cipher and additional inv_sbox for final round in decryption.

Based on "Peter Schwabe and Ko Stoffelen" AES implementation available [here](https://github.com/Ko-/aes-armcortexm).

32 bit LDR opcodes are forcefully aligned to 4 byte boundaries to prevent weird undocumented "feature" of cortex m4 that prevents pipelining of neighbouring loads. 
([here](https://community.arm.com/processors/f/discussions/4069/cortex-m3-pipelining-of-consecutive-ldr-instructions-to-different-memory-regions) is the 
only available hint over internet, also confirmed on real STM32F4)

LUT tables have to be placed in non cached and non waitstated SRAM memory with single word wide access, that is not crossing different memory domains (eg. AHB slaves).
FLASH memory simply cannot be used since vendors usually implements some kind of cache, wide prefetch buffers, and waitstates that will make cipher slower than generic or bitsliced/masked one.

### CM7_1T

Uses a single T table per enc/dec cipher and additional inv_sbox for final round in decryption.

Based on CM34 implementation, carefully rescheduled for dual issue pipeline, with 2x32 bit DTCM interface, to avoid data dependent issuing capability from even/odd DTCM words.
The speed differences can be illustrated by the following code:
```
	tick = DWT->CYCCNT;
	asm volatile(""
			"movw r9, #:lower16:AES_Te0 \n"
			"movt r9, #:upper16:AES_Te0 \n"
			"ldr r0, [r9, #0] \n"
			"ldr r0, [r9, #8] \n"
			"ldr r0, [r9, #16] \n"
			"ldr r0, [r9, #24] \n"
			""::: "r0","r9");
	tock = DWT->CYCCNT - tick - 1;

	printf("4 even loads, cycles: %lu\n", tock);

	tick = DWT->CYCCNT;
	asm volatile(""
			"movw r9, #:lower16:AES_Te0 \n"
			"movt r9, #:upper16:AES_Te0 \n"
			"ldr r0, [r9, #0] \n"
			"ldr r0, [r9, #4] \n"
			"ldr r0, [r9, #8] \n"
			"ldr r0, [r9, #12] \n"
			""::: "r0","r9");
	tock = DWT->CYCCNT - tick - 1;

	printf("4 linear loads, cycles: %lu\n", tock);
	printf("This is why any two LDRs cannot be placed next to each other\n");
```

Only DTCM memory can be used for LUT tables, since everything else is cached through AXI bus.
The effects of DMA access to DTCM memory when core have equal priority is unknown.

## Base ciphers performance (in cycles)

| Cipher function  | ? (0ws) - cortex m3 | STM32F4 (0ws) - cortex m4 | STM32F4 (7ws cached) - cortex m4 | cortex-m7 (icache) | cortex-m7 (?) |
|------------------|---------------------|---------------------------|----------------------------------|--------------------|---------------|
| `setEncKey<128>` |  |  | 305 | 178 |  |
| `setEncKey<192>` |  |  | 281 | 156/163* |  |
| `setEncKey<256>` |  |  | 441 | 240 |  |
| `encrypt<128>` |  |  | 689 | 380 |  |
| `encrypt<192>` |  |  | 817 | 448 |  |
| `encrypt<256>` |  |  | 945 | 513/516* |  |
| `encrypt_unrolled<128>` |  |  |  |  |  |
| `encrypt_unrolled<192>` |  |  |  |  |  |
| `encrypt_unrolled<256>` |  |  |  |  |  |
| `setDecKey<128>` |  |  | 723 | 530 |  |
| `setDecKey<192>` |  |  | 877 | 637/643* |  |
| `setDEcKey<256>` |  |  | 1031 | 749/755* |  |
| `decrypt<128>` |  |  | 694 | 387 |  |
| `decrypt<192>` |  |  | 822 | 455 |  |
| `decrypt<256>` |  |  | 950 | 521 |  |
| `decrypt_unrolled<128>` |  |  |  |  |  |
| `decrypt_unrolled<192>` |  |  |  |  |  |
| `decrypt_unrolled<256>` |  |  |  |  |  |

`*` Run to run variation due to branch prediction, code alignment, or something else beetwen testing code and implementations

## todo
- add block modes (CBC, CTR etc.)
- add bitsliced/masked implementations
- some renaming
- doxygen
- perf and cortex m3
- pre generation of lookups
- optimize cm7 rcon generation
- optimize cm7 for execution from itcm
- forward keyschedule_dec 
- optimize cm7 keyschedule_dec