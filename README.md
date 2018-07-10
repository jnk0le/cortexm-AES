# cortexm AES

FIPS 197 compliant software AES implementation optimized for real world cortex-m microcontrollers.


## notes
- Do not use ECB cipher mode for anything more than 16 bytes of plaintext data per key.
- Do not blindly trust in timming constantness of LUT based ciphers since it depends on many factors that are 
unknown or just implementation defined like section placement (you need to verify it, especially before use in production).
- None of the currently available implementations protects against power/EMI analysis attacks.
- do not use CM34_1T implementation on cortex-m7 since it is slower and will introduce timming leaks.
- Unrolled ciphers might perform slower than looped versions due to cache pressure and flash waitstates. (like STM32F4 with 1K ART cache and up to 8WS) 
- input/output buffers have to be word aligned due to use of ldm,stm,ldrd and strd instructions.

## implementations

### CM34_1T

cortex m3 and cortex m4 optimized implementation.
Uses a single T table per enc/dec cipher and additional inv_sbox for final round in decryption.

Based on "Peter Schwabe and Ko Stoffelen" AES implementation available [here](https://github.com/Ko-/aes-armcortexm).

32 bit LDR opcodes are forcefully aligned to 4 byte boundaries to prevent weird undocumented "feature" of cortex m4 that prevents pipelining of neighbouring loads. 
([here](https://community.arm.com/processors/f/discussions/4069/cortex-m3-pipelining-of-consecutive-ldr-instructions-to-different-memory-regions) is the 
only available hint over internet, also confirmed on real STM32F4)

LUT tables have to be placed in non cached and non waitstated SRAM memory with single word wide access, that is not crossing different memory domains (eg. AHB slaves).
FLASH memory simply cannot be used since vendors usually implements some kind of cache, wide prefetch buffers, and waitstates that will make cipher slower than generic or bitsliced/masked one.

### CM7_1T

cortex m7 optimized implementation.
Uses a single T table per enc/dec cipher and additional inv_sbox for final round in decryption.

Based on CM34 implementation, carefully reordered for dual issue pipeline, with 2x32 bit DTCM interface, to avoid data dependent issuing capability from even/odd DTCM words.
The time differences can be illustrated by the following code:
```
	tick = DWT->CYCCNT;
	asm volatile(""
			"movw r9, #:lower16:AES_Te0 \n"
			"movt r9, #:upper16:AES_Te0 \n"
			"ldr r0, [r9, #0] \n"
			"ldr r1, [r9, #8] \n"
			"ldr r2, [r9, #16] \n"
			"ldr r3, [r9, #24] \n"
			""::: "r0","r1","r2","r3","r9");
	tock = DWT->CYCCNT - tick - 1;

	printf("4 even loads, cycles: %lu\n", tock);

	tick = DWT->CYCCNT;
	asm volatile(""
			"movw r9, #:lower16:AES_Te0 \n"
			"movt r9, #:upper16:AES_Te0 \n"
			"ldr r0, [r9, #0] \n"
			"ldr r1, [r9, #4] \n"
			"ldr r2, [r9, #8] \n"
			"ldr r3, [r9, #12] \n"
			""::: "r0","r1","r2","r3","r9");
	tock = DWT->CYCCNT - tick - 1;

	printf("4 linear loads, cycles: %lu\n", tock);
	printf("This is why any two data dependent LDRs cannot be placed next to each other\n");
```

Only DTCM memory can be used for LUT tables, since everything else is cached through AXI bus.
The effects of DMA access to DTCM memory when core have equal priority is unknown.

## Base ciphers performance (in cycles)

| Cipher function     | STM32F1 (0ws/2ws) - cortex m3 | STM32F4 (0ws/7ws) - cortex m4 | STM32H7 (icache/itcm)* - cortex-m7 |
|---------------------|-------------------------------|-------------------------------|------------------------------------|
| `setEncKey<128>`    |  | 306      | 157 |
| `setEncKey<192>`    |  | 282      | 140 |
| `setEncKey<256>`    |  | 435      | 227 |
| `encrypt<128>`      |  | 690      | 340 |
| `encrypt<192>`      |  | 818      | 402 |
| `encrypt<256>`      |  | 946      | 464 |
| `enc_unrolled<128>` |  | 629/1022 | 315/314 |
| `enc_unrolled<192>` |  | 744/1219 | 373/372 | 
| `enc_unrolled<256>` |  | 857/1407 | 431/430 | 
| `setDecKey<128>`    |  | 723      | 518 |
| `setDecKey<192>`    |  | 877      | 630 |
| `setDEcKey<256>`    |  | 1031     | 742 |
| `decrypt<128>`      |  | 695      | 343/344 |
| `decrypt<192>`      |  | 825      | 405/406 |
| `decrypt<256>`      |  | 951      | 467/468 |
| `dec_unrolled<128>` |  | 631/1031 | 319/317 |
| `dec_unrolled<192>` |  | 748/1223 | 376/375 |
| `dec_unrolled<256>` |  | 859/1408 | 434/433 | 

Results are averaged over 1024 runs + one ommited (instruction) cache train run.

`*` When at least 2 unrolled functions are compiled in, everything else (including those functions) gets +9/10 cycles to execution (at least in [aes tests](aes_tests.hpp)).  
`long_call` attribute will only add a few cycles in both cases.

## todo
- add block modes (CBC, CTR etc.)
- add proper padding
- add bitsliced/masked implementations
- fix perf of unrolled functions
- doxygen
- perf and cortex m3
- pre generation of lookups
- forward keyschedule_dec 
- optimize cm7 keyschedule_dec