/*!
 * \file QKv2_sBOX_AES_encrypt.S
 * \brief
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

#if __riscv && (__riscv_xlen == 32)

#include "aes/target/QKv2_sBOX/QKv2_common.inc"

.text

// void QKv2_sBOX_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global QKv2_sBOX_AES_encrypt
.type   QKv2_sBOX_AES_encrypt,%function
QKv2_sBOX_AES_encrypt:
	c.addi sp, -16
	c.swsp s0, 0(sp)
	c.swsp s1, 4(sp)
	c.swsp ra, 8(sp)
	c.swsp a2, 12(sp) // stack out

	// a0 - rk ptr
	// a1 - in ptr
	// a2 - out ptr
	// a3 - rounds

	//rk_end-16 = rk + rounds * 16
	c.slli a3, 4
	add t1, a0, a3

	// load key
	c.lw a2, 0(a0)
	c.lw a3, 4(a0)

	li t2, 0x80808080

	c.lw a4, 8(a0)
	c.lw a5, 12(a0)
	addi s0, a0, 16

	// load input
	c.lw s1, 0(a1)
	c.lw a0, 4(a1)

	li t0, 0x1b1b1b1b

	c.xor a2, s1
	c.xor a3, a0
	c.lw a0, 8(a1)
	c.lw a1, 12(a1)

	lui ra, %hi(AES_sbox)
	addi ra, ra, %lo(AES_sbox)

	c.xor a4, a0
	c.xor a5, a1

	// global allocation
	// ra - sbox
	// t0 - 0x1b1b1b1b
	// t1 - final rk ptr
	// t2 - 0x80808080
	// s0 - current rk ptr

	// sp
	// +12 - out ptr
.balign 4
1:  // shiftrows and subbytes

	//columns are kept as little endian so right/left in shifts is in reverse wrt transposed canonical state representation
	// a2 - s00 | s10 | s20 | s30
	// a3 - s01 | s11 | s21 | s31
	// a4 - s02 | s12 | s22 | s32
	// a5 - s03 | s13 | s23 | s33

	//final
	// a2 - s00`| s11`| s22`| s33`
	// a3 - s01`| s12`| s23`| s30`
	// a4 - s02`| s13`| s20`| s31`
	// a5 - s03`| s10`| s21`| s32`

	srli s1, a2, 8

	zext.b a2, a2
	c.add a2, ra
	xw_.c.lbu a2, a2

	// current allocation
	// s1 - s10 | s20 | s30       //shifted #8
	// a0 -
	// a1 -
	// a2 - s00`|     |     |
	// a3 - s01 | s11 | s21 | s31
	// a4 - s02 | s12 | s22 | s32
	// a5 - s03 | s13 | s23 | s33

	srli a1, a3, 8
	zext.b a1, a1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 8

	c.or a2, a1

	srli a1, a4, 16
	zext.b a1, a1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 16

	c.or a2, a1

	srli a1, a5, 24
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 24

	c.or a2, a1

	// current allocation
	// s1 - s10 | s20 | s30       //shifted #8
	// a0 -
	// a1 -
	// a2 - s00`| s11`| s22`| s33`
	// a3 - s01 |  -  | s21 | s31
	// a4 - s02 | s12 |  -  | s32
	// a5 - s03 | s13 | s23 |  -

	srli a0, a5, 8

	zext.b a1, s1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 8

	zext.b a5, a5
	c.add a5, ra
	xw_.c.lbu a5, a5

	c.or a5, a1

	// current allocation
	// s1 -  -  | s20 | s30       //shifted #8
	// a0 - s13 | s23 |  -        //shifted #8
	// a1 -
	// a2 - s00`| s11`| s22`| s33`
	// a3 - s01 |  -  | s21 | s31
	// a4 - s02 | s12 |  -  | s32
	// a5 - s03`| s10`|     |

	srli a1, a3, 16
	zext.b a1, a1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 16

	c.or a5, a1

	srli a1, a4, 24
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 24

	c.or a5, a1

	// current allocation
	// s1 -  -  | s20 | s30       //shifted #8
	// a0 - s13 | s23 |  -        //shifted #8
	// a1 -
	// a2 - s00`| s11`| s22`| s33`
	// a3 - s01 |  -  |  -  | s31
	// a4 - s02 | s12 |  -  |  -
	// a5 - s03`| s10`| s21`| s32`

	// pack 2 coulumns to reduce pressure
	// adds 2 instructions overhead but gets rid of some stacking (+frees s0 for constant)

	c.srli s1, 8
	c.slli a0, 16
	c.or s1, a0

	// current allocation
	// s1 - s20 | s30 | s13 | s23      //col 1 shifted #16 //col 3 shifted #-8
	// a0 -
	// a1 -
	// a2 - s00`| s11`| s22`| s33`
	// a3 - s01 |  -  |  -  | s31
	// a4 - s02 | s12 |  -  |  -
	// a5 - s03`| s10`| s21`| s32`

	zext.b a0, a3

	c.srli a3, 24
	c.add a3, ra
	xw_.c.lbu a1, a3
	c.slli a1, 24

	c.add a0, ra
	xw_.c.lbu a3, a0

	// current allocation
	// s1 - s20 | s30 | s13 | s23      //col 1 shifted #16 //col 3 shifted #-8
	// a0 -
	// a1 -     |     |     | s31`
	// a2 - s00`| s11`| s22`| s33`
	// a3 - s01`|     |     |
	// a4 - s02 | s12 |  -  |  -
	// a5 - s03`| s10`| s21`| s32`

	zext.b a0, a4
	c.add a0, ra

	c.srli a4, 8
	zext.b a4, a4
	c.add a4, ra
	xw_.c.lbu a4, a4
	c.slli a4, 8

	c.or a3, a4

	xw_.c.lbu a4, a0

	// current allocation
	// s1 - s20 | s30 | s13 | s23      //col 1 shifted #16 //col 3 shifted #-8
	// a0 -
	// a1 -     |     |     | s31`
	// a2 - s00`| s11`| s22`| s33`
	// a3 - s01`| s12`|     |
	// a4 - s02`|     |     |
	// a5 - s03`| s10`| s21`| s32`

	zext.b a0, s1
	c.add a0, ra
	xw_.c.lbu a0, a0
	c.slli a0, 16

	c.or a4, a0
	c.or a4, a1 // can do later

	// current allocation
	// s1 -  -  | s30 | s13 | s23      //col 1 shifted #16 //col 3 shifted #-8
	// a0 -
	// a1 -
	// a2 - s00`| s11`| s22`| s33`
	// a3 - s01`| s12`|     |
	// a4 - s02`|     | s20`| s31`
	// a5 - s03`| s10`| s21`| s32`

	c.srli s1, 8
	zext.b a1, s1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 24

	c.or a3, a1

	c.srli s1, 8
	zext.b a1, s1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 8

	c.or a4, a1

	c.srli s1, 8
	zext.b a1, s1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 16

	c.or a3, a1

	// do mix columns as
	// tmp = s0 ^ s1 ^ s2 ^ s3
	// s0` ^= tmp ^ gmul2(s0^s1) // s1^s2^s3^gmul2(s0^s1)
	// s1` ^= tmp ^ gmul2(s1^s2) // s0^s2^s3^gmul2(s1^s2)
	// s2` ^= tmp ^ gmul2(s2^s3) // s0^s1^s3^gmul2(s2^s3)
	// S3` ^= tmp ^ gmul2(s3^s0) // s0^s1^s2^gmul2(s3^s0)

	//col 0
	srli a1, a2, 8
	slli a0, a2, 24
	c.or a1, a0
	c.xor a1, a2 // s0^s1 | s1^s2 | s2^s3 | s3^s0

	srli a0, a1, 16
	slli s1, a1, 16
	c.or a0, s1

	c.xor a0, a1 // s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	c.xor a2, a0 // s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	/* do quad multiplication according to:
	// mask = in & 0x80808080;
	// out = ((in & 0x7f7f7f7f) << 1) ^ ((mask - (mask >> 7)) & 0x1b1b1b1b);

	(in & 0x7f7f7f7f) - can be gotten in 2 ways - andn from 0x80808080 or xor with `mask`
	*/

	// a1 - (in) s0^s1 | s1^s2 | s2^s3 | s3^s0
	// a2 - s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	and a0, a1, t2
	c.xor a1, a0
	c.slli a1, 1 // can xor to result now

	// current allocation
	// s1 -
	// a0 - mask
	// a1 - (in &  0x7f7f7f7f) << 1
	// a2 - s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	srli s1, a0, 7
	c.sub a0, s1
	and a0, a0, t0 // do predicated reduction

	c.xor a1, a0
	c.xor a2, a1


	c.lw a0, 0(s0) // rk[0]
	c.xor a2, a0

	//col 1
	srli a1, a3, 8
	slli a0, a3, 24
	c.or a1, a0
	c.xor a1, a3 // s0^s1 | s1^s2 | s2^s3 | s3^s0

	srli a0, a1, 16
	slli s1, a1, 16
	c.or a0, s1

	c.xor a0, a1 // s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	c.xor a3, a0 // s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	and a0, a1, t2
	c.xor a1, a0
	c.slli a1, 1 // can xor to result now

	srli s1, a0, 7
	c.sub a0, s1
	and a0, a0, t0 // do predicated reduction

	c.xor a1, a0
	c.xor a3, a1

	c.lw a1, 4(s0) // rk[1]
	c.xor a3, a1

	//col 2
	srli a1, a4, 8
	slli a0, a4, 24
	c.or a1, a0
	c.xor a1, a4 // s0^s1 | s1^s2 | s2^s3 | s3^s0

	srli a0, a1, 16
	slli s1, a1, 16
	c.or a0, s1

	c.xor a0, a1 // s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	c.xor a4, a0 // s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	and a0, a1, t2
	c.xor a1, a0
	c.slli a1, 1 // can xor to result now

	srli s1, a0, 7
	c.sub a0, s1
	and a0, a0, t0 // do predicated reduction

	c.xor a1, a0
	c.xor a4, a1

	c.lw a0, 8(s0) // rk[2]
	c.xor a4, a0

	//col 3
	srli a1, a5, 8
	slli a0, a5, 24
	c.or a1, a0
	c.xor a1, a5 // s0^s1 | s1^s2 | s2^s3 | s3^s0

	srli a0, a1, 16
	slli s1, a1, 16
	c.or a0, s1

	c.xor a0, a1 // s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	c.xor a5, a0 // s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	and a0, a1, t2
	c.xor a1, a0
	c.slli a1, 1 // can xor to result now

	srli s1, a0, 7
	c.sub a0, s1
	and a0, a0, t0 // do predicated reduction

	c.xor a1, a0
	c.xor a5, a1

	c.lw a1, 12(s0) // rk[3]
	c.addi s0, 16
	c.xor a5, a1

	bne s0, t1, 1b

	// final round
	srli s1, a2, 8

	zext.b a2, a2
	c.add a2, ra
	xw_.c.lbu a2, a2

	// current allocation
	// s1 - s10 | s20 | s30       //shifted #8
	// a0 -
	// a1 -
	// a2 - s00`|     |     |
	// a3 - s01 | s11 | s21 | s31
	// a4 - s02 | s12 | s22 | s32
	// a5 - s03 | s13 | s23 | s33

	srli a1, a3, 8
	zext.b a1, a1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 8

	c.or a2, a1

	srli a1, a4, 16
	zext.b a1, a1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 16

	c.or a2, a1

	srli a1, a5, 24
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 24

	c.or a2, a1

	// current allocation
	// s1 - s10 | s20 | s30       //shifted #8
	// a0 -
	// a1 -
	// a2 - s00`| s11`| s22`| s33`
	// a3 - s01 |  -  | s21 | s31
	// a4 - s02 | s12 |  -  | s32
	// a5 - s03 | s13 | s23 |  -

	srli a0, a5, 8

	zext.b a1, s1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 8

	zext.b a5, a5
	c.add a5, ra
	xw_.c.lbu a5, a5

	c.or a5, a1

	// current allocation
	// s1 -  -  | s20 | s30       //shifted #8
	// a0 - s13 | s23 |  -        //shifted #8
	// a1 -
	// a2 - s00`| s11`| s22`| s33`
	// a3 - s01 |  -  | s21 | s31
	// a4 - s02 | s12 |  -  | s32
	// a5 - s03`| s10`|     |

	srli a1, a3, 16
	zext.b a1, a1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 16

	c.or a5, a1

	srli a1, a4, 24
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 24

	c.or a5, a1

	// current allocation
	// s1 -  -  | s20 | s30       //shifted #8
	// a0 - s13 | s23 |  -        //shifted #8
	// a1 -
	// a2 - s00`| s11`| s22`| s33`
	// a3 - s01 |  -  |  -  | s31
	// a4 - s02 | s12 |  -  |  -
	// a5 - s03`| s10`| s21`| s32`

	// pack 2 coulumns to reduce pressure
	// adds 2 instructions overhead but gets rid of some stacking (+frees s0 for constant)

	c.srli s1, 8
	c.slli a0, 16
	c.or s1, a0

	// current allocation
	// s1 - s20 | s30 | s13 | s23      //col 1 shifted #16 //col 3 shifted #-8
	// a0 -
	// a1 -
	// a2 - s00`| s11`| s22`| s33`
	// a3 - s01 |  -  |  -  | s31
	// a4 - s02 | s12 |  -  |
	// a5 - s03`| s10`| s21`| s32`

	zext.b a0, a3

	c.srli a3, 24
	c.add a3, ra
	xw_.c.lbu a1, a3
	c.slli a1, 24

	c.add a0, ra
	xw_.c.lbu a3, a0

	// current allocation
	// s1 - s20 | s30 | s13 | s23      //col 1 shifted #16 //col 3 shifted #-8
	// a0 -
	// a1 -     |     |     | s31`
	// a2 - s00`| s11`| s22`| s33`
	// a3 - s01`|     |     |
	// a4 - s02 | s12 |  -  |
	// a5 - s03`| s10`| s21`| s32`

	zext.b a0, a4
	c.add a0, ra

	c.srli a4, 8
	zext.b a4, a4
	c.add a4, ra
	xw_.c.lbu a4, a4
	c.slli a4, 8

	c.or a3, a4

	xw_.c.lbu a4, a0

	// current allocation
	// s1 - s20 | s30 | s13 | s23      //col 1 shifted #16 //col 3 shifted #-8
	// a0 -
	// a1 -     |     |     | s31`
	// a2 - s00`| s11`| s22`| s33`
	// a3 - s01`| s12`|     |
	// a4 - s02`|     |     |
	// a5 - s03`| s10`| s21`| s32`

	zext.b a0, s1
	c.add a0, ra
	xw_.c.lbu a0, a0
	c.slli a0, 16

	c.or a4, a0
	c.or a4, a1 // can do later

	// current allocation
	// s1 -  -  | s30 | s13 | s23      //col 1 shifted #16 //col 3 shifted #-8
	// a0 -
	// a1 -
	// a2 - s00`| s11`| s22`| s33`
	// a3 - s01`| s12`|     |
	// a4 - s02`|     | s20`| s31`
	// a5 - s03`| s10`| s21`| s32`

	c.srli s1, 8
	zext.b a1, s1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 24

	c.or a3, a1

	c.srli s1, 8
	zext.b a1, s1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 8

	c.or a4, a1

	c.srli s1, 8
	zext.b a1, s1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 16

	c.or a3, a1

	c.lw a0, 0(s0)
	c.xor a2, a0
	c.lw a1, 4(s0)
	c.xor a3, a1
	c.lw a0, 8(s0)
	c.xor a4, a0
	c.lw a1, 12(s0)
	c.xor a5, a1

	c.lwsp a0, 12(sp) // get out ptr
	c.sw a2, 0(a0)
	c.sw a3, 4(a0)
	c.sw a4, 8(a0)
	c.sw a5, 12(a0)

	c.lwsp s0, 0(sp)
	c.lwsp s1, 4(sp)
	c.lwsp ra, 8(sp)
	c.addi sp, 16
	ret

#endif
