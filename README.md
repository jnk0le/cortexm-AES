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

32 bit LDR opcodes are forcefully aligned to 4 byte boundaries to prevent weird undocumented "feature" of cortex m3 and m4 that prevents some pipelining of neighbouring loads. As well as other architecture specific optimizations.

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

## Base ciphers performance (in cycles per block)

| Cipher function     | STM32F1 (0ws/2ws) - cortex-m3 | STM32F4 (0ws/7ws) - cortex-m4 | STM32H7 - cortex-m7 |
|---------------------|-------------------------------|-------------------------------|---------------------|
| `setEncKey<128>`    | 302/355   | 306      | 157 |
| `setEncKey<192>`    | 278/348   | 282      | 140 |
| `setEncKey<256>`    | 402/516   | 435      | 227 |
| `encrypt<128>`      | 657/888   | 670      | 337 |
| `encrypt<192>`      | 779/1054  | 794      | 400 |
| `encrypt<256>`      | 901/1220  | 918      | 461 |
| `enc_unrolled<128>` | 604/869   | 607/1070 | 315* |
| `enc_unrolled<192>` | 714/1031  | 717/1270 | 373* | 
| `enc_unrolled<256>` | 824/1193  | 827/1470 | 431* | 
| `setDecKey<128>`    | 720/997   | 723      | 518 |
| `setDecKey<192>`    | 874/1211  | 877      | 630 |
| `setDEcKey<256>`    | 1028/1425 | 1031     | 742 |
| `decrypt<128>`      | 652/922   | 675      | 342 |
| `decrypt<192>`      | 772/1097  | 801      | 404 |
| `decrypt<256>`      | 892/1270  | 923      | 467 |
| `dec_unrolled<128>` | 607/880   | 610/1074 | 319* |
| `dec_unrolled<192>` | 717/1041  | 720/1274 | 376* |
| `dec_unrolled<256>` | 827/1204  | 830/1474 | 434* | 

Results are averaged over 1024 runs + one ommited (instruction) cache train run.

`*` When at least 2 unrolled functions are compiled in, everything else (including those functions) gets +9/10 cycles to execution (at least in [aes tests](aes_tests.hpp)).  
`long_call` attribute will only add a few cycles in both cases.

## Cipher modes performance (in cycles per byte) 

| Cipher function            | STM32F1 (0ws/2ws) - cortex-m3 | STM32F4 (0ws/7ws) - cortex-m4 | STM32H7 - cortex-m7 |
|----------------------------|-------------------------------|-------------------------------|---------------------|
| CBC_GENERIC<128> enc(+dec) | 43.08(-0.3)/56.97(+2.2)       | 43.9(+0.3)                    | 22.01(+0.4)         |
| CBC_GENERIC<192> enc(+dec) | 50.71(-0.3)/67.22(+2.4)       | 51.65(+0.3)                   | 25.89(+0.5)         |
| CBC_GENERIC<256> enc(+dec) | 58.33(-0.3)/77.47(+3.1)       | 59.4(+0.3)                    | 29.76(+0.4)         |
| CTR_GENERIC<128>           | 42.32/56.32                   | 43.07                         | 21.63               |
| CTR_GENERIC<192>           | 49.95/66.88                   | 50.82                         | 25.50               |
| CTR_GENERIC<256>           | 57.57/76.69                   | 58.57                         | 29.38               |
| CTR<128>                   | 33.78/45.98                   | 34.60                         | 17.65               |
| CTR<192>                   | 41.41/56.48                   | 42.35                         | 21.52               |
| CTR<256>                   | 49.03/66.98                   | 50.10                         | 25.40               |
| CTR_unrolled<128>          | 31.09/44.80                   | 31.47/55.43                   | 16.64               |
| CTR_unrolled<192>          | 37.97/54.98                   | 38.34/67.93                   | 20.27               |
| CTR_unrolled<256>          | 44.84/65.11                   | 45.22/80.43                   | 23.89               |

## todo
- add proper padding
- add bitsliced/masked implementations
- fix perf of cm7 unrolled functions
- doxygen
- pre generation of lookups
- forward keyschedule_dec
- optimize cm7 keyschedule_dec