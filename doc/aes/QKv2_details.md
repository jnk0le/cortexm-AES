# "QingKeV2" (ch32v003)

Optimized for ilp32e ABI\
Exploits WCH "xw" extension without the need for compiler support.

## base impl

### QKv2_sBOX

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

## perfomance

| Cipher function  | ch32v003 (0ws/1ws) - QKv2_sBOX |
|------------------|------------------|
| `setEncKey<128>` | 461/478 |
| `setEncKey<256>` | 582/622 |
| `encrypt<128>`   | 1835/2109 |
| `encrypt<256>`   | 2571/2965 |
| `setDecKey<128>` | 0 |
| `setDecKey<256>` | 0 |
| `decrypt<128>`   | 2641/3235 |
| `decrypt<256>`   | 3733/4587 |

## specific function size

| Function | code size in bytes | stack usage in bytes | notes |
|----------|--------------------|----------------------|-------|
| `QKv2_AES128_keyschedule_enc` | 80 | 4 | uses sbox table |
| `QKv2_AES192_keyschedule_enc` | 138 | 8 | uses sbox table |
| `QKv2_AES256_keyschedule_enc` | 216 | 12 | uses sbox table |
| `QKv2_sBOX_AES_encrypt` | 730 | 16 | uses sbox table |
| `QKv2_sBOX_AES_decrypt` | 996 | 20 | uses inv_sbox table |
