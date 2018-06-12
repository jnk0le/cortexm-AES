# cortexm AES

FIPS 197 compliant software AES implementation optimized for real world cortex-m3/4 microcontrollers.
Based on "Peter Schwabe and Ko Stoffelen" AES implementation available [here](https://github.com/Ko-/aes-armcortexm).

## notes

- Do not use ECB cipher mode for anything more than 16 bytes of plaintext data.

- To avoid data dependent timming leakage, any used lookup table have to be located in non cached and non 
 waitstated SRAM memory with single word wide access, that is not crossing different memory domains (eg. AHB slaves).
 
- Timming constantness still depends on many factors and needs to be verified before use.

- none of the currently available implementations protects against power/EMI analysis attacks.

## todo
- add block modes (CBC, CTR etc.)
- add bitsliced/masked implementations
- some renaming
- doxygen
- tests
- examples
- perf and cortex m3
- pre generation of lookups
- lut alignment