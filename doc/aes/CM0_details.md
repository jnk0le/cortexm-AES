# cortex-m0/m0+

## base impl

### CM0_sBOX

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

### CM0_FASTMULsBOX

Faster than CM0sBOX only when running on core with single cycle multiplier (used for predicated reduction in mixcolumns multiplication)

Implemented similarly to CM0sBOX but with `gmul2()` implementend as:

```
out = ((in & 0x7f7f7f7f) << 1) ^ (((in & 0x80808080) >> 7)) * 0x1b);

// or equivalent sequence to perform shifts first in order to avoid extra moves
out = ((in << 1) & 0xfefefefe) ^ (((in >> 7) & 0x01010101) * 0x1b)
```

### CM0_d4T


## perfomance

| Cipher function  | STM32F0 (0ws/1ws) - CM0_sBOX | STM32F0 (0ws/1ws) - CM0_FASTMULsBOX | STM32F0 (0ws/1ws) - CM0_d4T |
|------------------|------------------------------|-------------------------------------|------------------------------|
| `setEncKey<128>` | 399/415 | (sBOX) |  |
| `setEncKey<192>` | 375/389 | (sBOX) |  |
| `setEncKey<256>` | 568/586 | (sBOX) |  |
| `encrypt<128>`   | 1666/1680 | 1587/1600 | 1131/? |
| `encrypt<192>`   | 2000/2016 | 1905/1920 |  |
| `encrypt<256>`   | 2334/2352 | 2223/2240 | 1567/? |
| `setDecKey<128>` | 0 | 0 | 0 |
| `setDecKey<192>` | 0 | 0 | 0 |
| `setDecKey<256>` | 0 | 0 | 0 |
| `decrypt<128>`   | 2567/2580 | 2387/2400 |  |
| `decrypt<192>`   | 3099/3114 | 2879/2894 |  |
| `decrypt<256>`   | 3631/3648 | 3371/3388 |  |

STM32F0 is cortex-m0 (prefetch enabled for 1ws, no prefetch leads to ~45% performance degradation)


## specific function size

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------| 
| `CM0_sBOX_AES128_keyschedule_enc` | 80 | 16 | uses sbox table |
| `CM0_sBOX_AES192_keyschedule_enc` | 88 | 20(24) | uses sbox table |
| `CM0_sBOX_AES256_keyschedule_enc` | 164 | 32 | uses sbox table |
| `CM0_sBOX_AES_encrypt` | 508 | 40 | uses sbox table |
| `CM0_sBOX_AES_decrypt` | 712 | 40 | uses inv_sbox table |
| `CM0_FASTMULsBOX_AES_encrypt` | 480 | 36(40) | uses sbox table, requires single cycle multiplier |
| `CM0_FASTMULsBOX_AES_decrypt` | 672 | 40 | uses inv_sbox table, requires single cycle multiplier |4
| `CM0_d4T_AES_encrypt` |  |  | uses d4T and sbox table |

code sizes include pc-rel constants and their padding

extra 4 bytes on stack comes from aligning stack to 8 bytes on ISR entry.
