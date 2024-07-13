# cortex-m3/m4

32 bit LDR opcodes are aligned to 4 byte boundaries (instructions not data) to prevent weird 
undocumented "feature" of cortex-m3/4 that prevents some pipelining of neighbouring loads.

LUT tables have to be placed in non cached and non waitstated SRAM memory with 32bit 
wide access, that is not crossing different memory domains (eg. AHB slaves).

## base impl

### CM3_sBOX

### CM3_1T

cortex m3 and cortex m4 optimized implementation.
Uses a single T table per enc/dec cipher and additional inv_sbox for final round in decryption.

Originally based on "Peter Schwabe and Ko Stoffelen" AES implementation available 
[here](https://github.com/Ko-/aes-armcortexm).

### CM3_1T_unrolled

Same as CM3_1T but uses unrollend enc/dec functions

### CM3_1T_deconly

Same as CM3_1T. Uses sbox table in key expansions instead of Te2 to reduce pressure on SRAM for decryption only use cases

### CM3_1T_unrolled_deconly

Same as CM3_1T_deconly but uses unrollend enc/dec functions

### CM4_DSPsBOX

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

| Cipher function  | STM32F1 (0ws/2ws) - CM3_1T | STM32F1 (0ws/2ws) - CM3_sBOX | STM32F4 (0ws/5ws) - CM3_1T | STM32F4 - CM4_DSPsBOX |
|------------------|----------------------------|------------------------------|----------------------------|-----------------------|
| `setEncKey<128>`        | 302/358  |  | 302 | 302 |
| `setEncKey<192>`        | 276/311  |  | 276 | 277 |
| `setEncKey<256>`        | 378/485  |  | 379 | 381 |
| `encrypt<128>`          | 627/842  |  | 626 | 852 |
| `encrypt<192>`          | 743/997 |  | 742 | 1020 |
| `encrypt<256>`          | 859/1158 |  | 858 | 1188 |
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

## specific function size

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------|
| `CM3_1T_AES128_keyschedule_enc` | 100 | 24 | uses Te2 table |
| `CM3_1T_AES192_keyschedule_enc` | 100 | 32 | uses Te2 table |
| `CM3_1T_AES256_keyschedule_enc` | 178 | 44(48) | uses Te2 table |
| `CM3_1T_AES_keyschedule_dec` | 92 | 12(16) | uses Te2 and Td2 table |
| `CM3_1T_AES_keyschedule_dec_noTe` | 86 | 12(16) | uses sbox and Td2 table |
| `CM3_1T_AES_encrypt` | 404 | 40 | uses Te2 table |
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
