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

Uses the diffused 4 T tables, which is more efficient than 1T or 4T as it doesn't require
rotations or increasing register pressure with 4 pointers.

Fully resistant to bank timming attacks on 2 or 4 banked (by word
striping) SRAM memories (e.g. SRAM0 in rp2040)

### CM0_d4T_FAST

Same as d4T but uses basic sbox/inv_sbox in final round.
Forward encryption consumes extra 256 bytes. (sbox)

Can be used on typical unstriped memories.

Requires single cycle multipler for inverse keyschedule

## perfomance

| Cipher function  | STM32F0 (0ws/1ws) - CM0_sBOX | STM32F0 (0ws/1ws) - CM0_FASTMULsBOX | STM32F0 (0ws/1ws) - CM0_d4T | STM32F0 (0ws/1ws) - CM0_d4T_FAST |
|------------------|------------------------------|-------------------------------------|------------------------------|------------------------------|
| `setEncKey<128>` | 399/414 | (sBOX) | 439/? | (sBOX) |
| `setEncKey<256>` | 568/579 | (sBOX) | 620/? | (sBOX) |
| `encrypt<128>`   | 1646/1659 | 1567/1579 | 1152/? | 1138/? |
| `encrypt<256>`   | 2306/2323 | 2195/2211 | 1588/? | 1574/? |
| `setDecKey<128>` | 0 | 0 | 1604/? | 1500/? |
| `setDecKey<256>` | 0 | 0 | 2308/? | 2156/? |
| `decrypt<128>`   | 2537/2551 | 2351/2364 | 1155/? | 1132/? |
| `decrypt<256>`   | 3589/3607 | 3323/3339 | 1591/? | 1568/? |

STM32F0 is cortex-m0 (prefetch enabled for 1ws, no prefetch leads to ~45% performance degradation)


## specific function size

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------|
| `CM0_sBOX_AES128_keyschedule_enc` | 80 | 16 | uses sbox table |
| `CM0_sBOX_AES192_keyschedule_enc` | 88 | 20(24) | uses sbox table |
| `CM0_sBOX_AES256_keyschedule_enc` | 168 | 32 | uses sbox table |
| `CM0_sBOX_AES_encrypt` | 500 | 40 | uses sbox table |
| `CM0_sBOX_AES_decrypt` | 700 | 40 | uses inv_sbox table |
| `CM0_FASTMULsBOX_AES_encrypt` | 472 | 36(40) | uses sbox table, requires single cycle multiplier |
| `CM0_FASTMULsBOX_AES_decrypt` | 660 | 40 | uses inv_sbox table, requires single cycle multiplier |
| `CM0_d4T_AES128_keyschedule_enc` | 88 | 16 | uses d4Te table |
| `CM0_d4T_AES192_keyschedule_enc` | 94 | 20(24) | uses d4Te table |
| `CM0_d4T_AES256_keyschedule_enc` | 182 | 32 | uses d4Te table |
| `CM0_d4T_AES_keyschedule_dec` | 88 | 12(16) | uses d4Te and d4Td tables |
| `CM0_FASTMUL_AES_keyschedule_dec` | 96 | 20(24) | requires single cycle multiplier |
| `CM0_d4T_AES_encrypt` | 398 | 32 | uses d4Te table |
| `CM0_d4T_AES_decrypt` | 408 | 32 | uses d4Td and d4Td4 tables |
| `CM0_d4T_FAST_AES_encrypt` | 368 | 32 | uses d4Te and sbox table |
| `CM0_d4T_FAST_AES_decrypt` | 376 | 32 | uses d4Td and inv_sbox tables |

code sizes include pc-rel constants and their padding

extra 4 bytes on stack comes from aligning stack to 8 bytes on ISR entry.
