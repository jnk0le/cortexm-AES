/*!
 * \file QKv2_sBOX_AES_decrypt.S
 * \brief
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */


#if __riscv && (__riscv_xlen == 32)

#include "aes/target/QKv2_sBOX/QKv2_common.inc"

.text

.balign 4
// void QKv2_sBOX_AES_decrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global QKv2_sBOX_AES_decrypt
.type   QKv2_sBOX_AES_decrypt,%function
QKv2_sBOX_AES_decrypt:
	c.addi sp, -16
	c.swsp s0, 0(sp)
	c.swsp s1, 4(sp)
	c.swsp ra, 8(sp)
	c.swsp a2, 12(sp) // stack out

	// a0 - rk ptr
	// a1 - in ptr
	// a2 - out ptr
	// a3 - rounds

	addi t1, a0, 16 // final rk

	//create end, rk+0 + rounds * 16
	c.slli a3, 4
	c.add a0, a3

	lui ra, %hi(AES_inv_sbox)
	addi ra, ra, %lo(AES_inv_sbox)

	// load key
	c.lw a2, 0(a0)
	c.lw a3, 4(a0)
	c.lw a4, 8(a0)
	c.lw a5, 12(a0)

	// load input
	c.lw s0, 0(a1)
	c.lw s1, 4(a1)
	// initial addroundkey
	c.xor a2, s0
	c.xor a3, s1

	c.lw s0, 8(a1)
	c.lw s1, 12(a1)
	c.xor a4, s0
	c.xor a5, s1

	li t0, 0x1b1b1b1b
	li t2, 0x80808080

	// global allocation
	// ra - inv_sbox
	// t0 - 0x1b1b1b1b
	// t1 - final rk ptr
	// t2 - 0x80808080
	// a0 - current rk ptr

	// sp
	// +12 - out ptr

.balign 4
1:	//inv shiftrows and invsubbytes

	//columns are kept as little endian so right/left in shifts is in reverse wrt transposed canonical state representation
	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 | s33

	//final
	// r4 - s00`| s13`| s22`| s31`
	// r5 - s01`| s10`| s23`| s32`
	// r6 - s02`| s11`| s20`| s33`
	// r7 - s03`| s12`| s21`| s30`

	srli s0, a2, 8

	zext.b a2, a2
	c.add a2, ra
	xw_.c.lbu a2, a2

	// current allocation
	// s0 - s10 | s20 | s30       //shifted #8
	// s1 -
	// a1 -
	// a2 - s00`|     |     |
	// a3 - s01 | s11 | s21 | s31
	// a4 - s02 | s12 | s22 | s32
	// a5 - s03 | s13 | s23 | s33

	srli s1, a5, 8
	zext.b s1, s1
	c.add s1, ra
	xw_.c.lbu s1, s1
	c.slli s1, 8

	c.or a2, s1

	srli s1, a4, 16
	zext.b s1, s1
	c.add s1, ra
	xw_.c.lbu s1, s1
	c.slli s1, 16

	c.or a2, s1

	srli s1, a3, 24
	zext.b s1, s1
	c.add s1, ra
	xw_.c.lbu s1, s1
	c.slli s1, 24

	c.or a2, s1

	// current allocation
	// s0 - s10 | s20 | s30       //shifted #8
	// s1 -
	// a1 -
	// a2 - s00`| s13`| s22`| s31`
	// a3 - s01 | s11 | s21 |  -
	// a4 - s02 | s12 |  -  | s32
	// a5 - s03 |  -  | s23 | s33

	srli s1, a3, 8

	zext.b a1, s0
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 8

	zext.b a3, a3
	c.add a3, ra
	xw_.c.lbu a3, a3

	c.or a3, a1

	// current allocation
	// s0 -  -  | s20 | s30       //shifted #8
	// s1 - s11 | s21 |  -        //shifted #8
	// a1 -
	// a2 - s00`| s13`| s22`| s31`
	// a3 - s01`| s10`|     |
	// a4 - s02 | s12 |  -  | s32
	// a5 - s03 |  -  | s23 | s33

	// pack 2 coulumns to reduce pressure
	// adds 2 instructions overhead but gets rid of spills (+frees s0 for constant)

	c.srli s0, 8
	c.slli s1, 16
	c.or s0, s1

	// current allocation
	// s0 - s20 | s30 | s11 | s21 //col 0 shifted #16 //col 1 shifted #-8
	// s1 -
	// a1 -
	// a2 - s00`| s13`| s22`| s31`
	// a3 - s01`| s10`|     |
	// a4 - s02 | s12 |  -  | s32
	// a5 - s03 |  -  | s23 | s33


	srli a1, a5, 16
	zext.b a1, a1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 16

	c.or a3, a1

	// current allocation
	// s0 - s20 | s30 | s11 | s21 //col 0 shifted #16 //col 1 shifted #-8
	// s1 -
	// a1 -
	// a2 - s00`| s13`| s22`| s31`
	// a3 - s01`| s10`| s23`|
	// a4 - s02 | s12 |  -  | s32
	// a5 - s03 |  -  |  -  | s33

	zext.b a1, a5

	c.srli a5, 24
	c.add a5, ra
	xw_.c.lbu s1, a5
	c.slli s1, 24

	c.add a1, ra
	xw_.c.lbu a5, a1

	// current allocation
	// s0 - s20 | s30 | s11 | s21 //col 0 shifted #16 //col 1 shifted #-8
	// s1 -     |     |     | s33`
	// a1 -
	// a2 - s00`| s13`| s22`| s31`
	// a3 - s01`| s10`| s23`|
	// a4 - s02 | s12 |  -  | s32
	// a5 - s03`|     |     |

	srli a1, a4, 8
	zext.b a1, a1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 8

	c.or a5, a1

	zext.b a1, a4
	c.add a1, ra
	xw_.c.lbu a1, a1

	c.srli a4, 24
	c.add a4, ra
	xw_.c.lbu a4, a4
	c.slli a4, 24

	c.or a3, a4

	// current allocation
	// s0 - s20 | s30 | s11 | s21 //col 0 shifted #16 //col 1 shifted #-8
	// s1 -     |     |     | s33`
	// a1 - s02`|     |     |
	// a2 - s00`| s13`| s22`| s31`
	// a3 - s01`| s10`| s23`| s32`
	// a4 -
	// a5 - s03`| s12`|     |

	zext.b a4, s0
	c.add a4, ra
	xw_.c.lbu a4, a4
	c.slli a4, 16

	c.or a4, a1
	c.or a4, s1

	// current allocation
	// s0 -  -  | s30 | s11 | s21 //col 0 shifted #16 //col 1 shifted #-8
	// s1 -
	// a1 -
	// a2 - s00`| s13`| s22`| s31`
	// a3 - s01`| s10`| s23`| s32`
	// a4 - s02`|     | s20`| s33`
	// a5 - s03`| s12`|     |

	c.srli s0, 8
	zext.b a1, s0
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 24

	c.or a5, a1

	c.srli s0, 8
	zext.b a1, s0
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 8

	c.or a4, a1

	c.srli s0, 8
	zext.b s0, s0
	c.add s0, ra
	xw_.c.lbu s0, s0
	c.slli s0, 16

	c.or a5, s0

	// current allocation
	// a2 - s00`| s13`| s22`| s31`
	// a3 - s01`| s10`| s23`| s32`
	// a4 - s02`| s11`| s20`| s33`
	// a5 - s03`| s12`| s21`| s30`

	c.addi a0, -16

	//addroundkey
	c.lw s0, 0(a0)
	c.lw s1, 4(a0)
	c.xor a2, s0
	c.xor a3, s1

	c.lw s0, 8(a0)
	c.lw s1, 12(a0)
	c.xor a4, s0
	c.xor a5, s1

	//invmixcolums

	//expand S{1} to S{2}, S{4}, S{8}
	//all of them have to be preserved

	/* do quad multiplication according to:
	// mask = in & 0x80808080;
	// out = ((in & 0x7f7f7f7f) << 1) ^ ((mask - (mask >> 7)) & 0x1b1b1b1b);

	(in & 0x7f7f7f7f) - can be gotten in 2 ways - andn from 0x80808080 or xor with `mask`
	*/

	//xxx
	c.addi sp, -4
	c.swsp a0, 0(sp)

	//col 0
	and a1, a2, t2 // mask
	xor a0, a2, a1 // equivalent to & 0x7f

	srli s1, a1, 7
	c.sub a1, s1
	and a1, a1, t0 // get predicated reduction

	c.slli a0, 1

	c.xor a1, a0 // S{2}

	and a0, a1, t2 // mask
	xor s1, a1, a0 // equivalent to & 0x7f

	srli s0, a0, 7
	c.sub a0, s0
	and a0, a0, t0 // get predicated reduction

	c.slli s1, 1

	c.xor a0, s1 // S{4}

	and s1, a0, t2 // mask
	srli s0, s1, 7
	c.sub s1, s0
	and s1, s1, t0 // get predicated reduction

	not s0, t2 // can't use mask to xor
	c.and s0, a0
	c.slli s0, 1

	c.xor s1, s0 // S{8}

	// current allocation
	// s0 -
	// s1 - S{8}
	// a0 - S{4}
	// a1 - S{2}
	// a2 - S{1}

	c.xor a2, s1 // S{9}
	c.xor s1, a0
	c.xor s1, a1 // S{e}
	c.xor a1, a2 // S{b}
	c.xor a0, a2 // S{d}

	srli s0, a2, 24
	c.slli a2, 8
	c.or a2, s0 // ror24(S{9})

	c.xor a2, s1 // S{e}

	srli s0, a1, 8
	c.slli a1, 24
	c.or a1, s0

	c.xor a2, a1 // ror8(S{b})

	srli s0, a0, 16
	c.slli a0, 16
	c.or a0, s0

	c.xor a2, a0 // ror16(S{d})

	//col 1
		and a1, a3, t2 // mask
	xor a0, a3, a1 // equivalent to & 0x7f

	srli s1, a1, 7
	c.sub a1, s1
	and a1, a1, t0 // get predicated reduction

	c.slli a0, 1

	c.xor a1, a0 // S{2}

	and a0, a1, t2 // mask
	xor s1, a1, a0 // equivalent to & 0x7f

	srli s0, a0, 7
	c.sub a0, s0
	and a0, a0, t0 // get predicated reduction

	c.slli s1, 1

	c.xor a0, s1 // S{4}

	and s1, a0, t2 // mask
	srli s0, s1, 7
	c.sub s1, s0
	and s1, s1, t0 // get predicated reduction

	not s0, t2 // can't use mask to xor
	c.and s0, a0
	c.slli s0, 1

	c.xor s1, s0 // S{8}

	// current allocation
	// s0 -
	// s1 - S{8}
	// a0 - S{4}
	// a1 - S{2}
	// a3 - S{1}

	c.xor a3, s1 // S{9}
	c.xor s1, a0
	c.xor s1, a1 // S{e}
	c.xor a1, a3 // S{b}
	c.xor a0, a3 // S{d}

	srli s0, a3, 24
	c.slli a3, 8
	c.or a3, s0 // ror24(S{9})

	c.xor a3, s1 // S{e}

	srli s0, a1, 8
	c.slli a1, 24
	c.or a1, s0

	c.xor a3, a1 // ror8(S{b})

	srli s0, a0, 16
	c.slli a0, 16
	c.or a0, s0

	c.xor a3, a0 // ror16(S{d})

	//col 2
		and a1, a4, t2 // mask
	xor a0, a4, a1 // equivalent to & 0x7f

	srli s1, a1, 7
	c.sub a1, s1
	and a1, a1, t0 // get predicated reduction

	c.slli a0, 1

	c.xor a1, a0 // S{2}

	and a0, a1, t2 // mask
	xor s1, a1, a0 // equivalent to & 0x7f

	srli s0, a0, 7
	c.sub a0, s0
	and a0, a0, t0 // get predicated reduction

	c.slli s1, 1

	c.xor a0, s1 // S{4}

	and s1, a0, t2 // mask
	srli s0, s1, 7
	c.sub s1, s0
	and s1, s1, t0 // get predicated reduction

	not s0, t2 // can't use mask to xor
	c.and s0, a0
	c.slli s0, 1

	c.xor s1, s0 // S{8}

	// current allocation
	// s0 -
	// s1 - S{8}
	// a0 - S{4}
	// a1 - S{2}
	// a4 - S{1}

	c.xor a4, s1 // S{9}
	c.xor s1, a0
	c.xor s1, a1 // S{e}
	c.xor a1, a4 // S{b}
	c.xor a0, a4 // S{d}

	srli s0, a4, 24
	c.slli a4, 8
	c.or a4, s0 // ror24(S{9})

	c.xor a4, s1 // S{e}

	srli s0, a1, 8
	c.slli a1, 24
	c.or a1, s0

	c.xor a4, a1 // ror8(S{b})

	srli s0, a0, 16
	c.slli a0, 16
	c.or a0, s0

	c.xor a4, a0 // ror16(S{d})

	//col 3
		and a1, a5, t2 // mask
	xor a0, a5, a1 // equivalent to & 0x7f

	srli s1, a1, 7
	c.sub a1, s1
	and a1, a1, t0 // get predicated reduction

	c.slli a0, 1

	c.xor a1, a0 // S{2}

	and a0, a1, t2 // mask
	xor s1, a1, a0 // equivalent to & 0x7f

	srli s0, a0, 7
	c.sub a0, s0
	and a0, a0, t0 // get predicated reduction

	c.slli s1, 1

	c.xor a0, s1 // S{4}

	and s1, a0, t2 // mask
	srli s0, s1, 7
	c.sub s1, s0
	and s1, s1, t0 // get predicated reduction

	not s0, t2 // can't use mask to xor
	c.and s0, a0
	c.slli s0, 1

	c.xor s1, s0 // S{8}

	// current allocation
	// s0 -
	// s1 - S{8}
	// a0 - S{4}
	// a1 - S{2}
	// a5 - S{1}

	c.xor a5, s1 // S{9}
	c.xor s1, a0
	c.xor s1, a1 // S{e}
	c.xor a1, a5 // S{b}
	c.xor a0, a5 // S{d}

	srli s0, a5, 24
	c.slli a5, 8
	c.or a5, s0 // ror24(S{9})

	c.xor a5, s1 // S{e}

	srli s0, a1, 8
	c.slli a1, 24
	c.or a1, s0

	c.xor a5, a1 // ror8(S{b})

	srli s0, a0, 16
	c.slli a0, 16
	c.or a0, s0

	c.xor a5, a0 // ror16(S{d})

	//xxx
	c.lwsp a0, 0(sp)
	c.addi sp, 4




	bne a0, t1, 1b


	srli s0, a2, 8

	zext.b a2, a2
	c.add a2, ra
	xw_.c.lbu a2, a2

	// current allocation
	// s0 - s10 | s20 | s30       //shifted #8
	// s1 -
	// a1 -
	// a2 - s00`|     |     |
	// a3 - s01 | s11 | s21 | s31
	// a4 - s02 | s12 | s22 | s32
	// a5 - s03 | s13 | s23 | s33

	srli s1, a5, 8
	zext.b s1, s1
	c.add s1, ra
	xw_.c.lbu s1, s1
	c.slli s1, 8

	c.or a2, s1

	srli s1, a4, 16
	zext.b s1, s1
	c.add s1, ra
	xw_.c.lbu s1, s1
	c.slli s1, 16

	c.or a2, s1

	srli s1, a3, 24
	zext.b s1, s1
	c.add s1, ra
	xw_.c.lbu s1, s1
	c.slli s1, 24

	c.or a2, s1

	// current allocation
	// s0 - s10 | s20 | s30       //shifted #8
	// s1 -
	// a1 -
	// a2 - s00`| s13`| s22`| s31`
	// a3 - s01 | s11 | s21 |  -
	// a4 - s02 | s12 |  -  | s32
	// a5 - s03 |  -  | s23 | s33

	srli s1, a3, 8

	zext.b a1, s0
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 8

	zext.b a3, a3
	c.add a3, ra
	xw_.c.lbu a3, a3

	c.or a3, a1

	// current allocation
	// s0 -  -  | s20 | s30       //shifted #8
	// s1 - s11 | s21 |  -        //shifted #8
	// a1 -
	// a2 - s00`| s13`| s22`| s31`
	// a3 - s01`| s10`|     |
	// a4 - s02 | s12 |  -  | s32
	// a5 - s03 |  -  | s23 | s33

	// pack 2 coulumns to reduce pressure
	// adds 2 instructions overhead but gets rid of spills (+frees s0 for constant)

	c.srli s0, 8
	c.slli s1, 16
	c.or s0, s1

	// current allocation
	// s0 - s20 | s30 | s11 | s21 //col 0 shifted #16 //col 1 shifted #-8
	// s1 -
	// a1 -
	// a2 - s00`| s13`| s22`| s31`
	// a3 - s01`| s10`|     |
	// a4 - s02 | s12 |  -  | s32
	// a5 - s03 |  -  | s23 | s33


	srli a1, a5, 16
	zext.b a1, a1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 16

	c.or a3, a1

	// current allocation
	// s0 - s20 | s30 | s11 | s21 //col 0 shifted #16 //col 1 shifted #-8
	// s1 -
	// a1 -
	// a2 - s00`| s13`| s22`| s31`
	// a3 - s01`| s10`| s23`|
	// a4 - s02 | s12 |  -  | s32
	// a5 - s03 |  -  |  -  | s33

	zext.b a1, a5

	c.srli a5, 24
	c.add a5, ra
	xw_.c.lbu s1, a5
	c.slli s1, 24

	c.add a1, ra
	xw_.c.lbu a5, a1

	// current allocation
	// s0 - s20 | s30 | s11 | s21 //col 0 shifted #16 //col 1 shifted #-8
	// s1 -     |     |     | s33`
	// a1 -
	// a2 - s00`| s13`| s22`| s31`
	// a3 - s01`| s10`| s23`|
	// a4 - s02 | s12 |  -  | s32
	// a5 - s03`|     |     |

	srli a1, a4, 8
	zext.b a1, a1
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 8

	c.or a5, a1

	zext.b a1, a4
	c.add a1, ra
	xw_.c.lbu a1, a1

	c.srli a4, 24
	c.add a4, ra
	xw_.c.lbu a4, a4
	c.slli a4, 24

	c.or a3, a4

	// current allocation
	// s0 - s20 | s30 | s11 | s21 //col 0 shifted #16 //col 1 shifted #-8
	// s1 -     |     |     | s33`
	// a1 - s02`|     |     |
	// a2 - s00`| s13`| s22`| s31`
	// a3 - s01`| s10`| s23`| s32`
	// a4 -
	// a5 - s03`| s12`|     |

	zext.b a4, s0
	c.add a4, ra
	xw_.c.lbu a4, a4
	c.slli a4, 16

	c.or a4, a1
	c.or a4, s1

	// current allocation
	// s0 -  -  | s30 | s11 | s21 //col 0 shifted #16 //col 1 shifted #-8
	// s1 -
	// a1 -
	// a2 - s00`| s13`| s22`| s31`
	// a3 - s01`| s10`| s23`| s32`
	// a4 - s02`|     | s20`| s33`
	// a5 - s03`| s12`|     |

	c.srli s0, 8
	zext.b a1, s0
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 24

	c.or a5, a1

	c.srli s0, 8
	zext.b a1, s0
	c.add a1, ra
	xw_.c.lbu a1, a1
	c.slli a1, 8

	c.or a4, a1

	c.srli s0, 8
	zext.b s0, s0
	c.add s0, ra
	xw_.c.lbu s0, s0
	c.slli s0, 16

	c.or a5, s0

	// current allocation
	// a2 - s00`| s13`| s22`| s31`
	// a3 - s01`| s10`| s23`| s32`
	// a4 - s02`| s11`| s20`| s33`
	// a5 - s03`| s12`| s21`| s30`

	c.addi a0, -16

	//addroundkey
	c.lw s0, 0(a0)
	c.lw s1, 4(a0)
	c.xor a2, s0
	c.xor a3, s1

	c.lw s0, 8(a0)
	c.lw s1, 12(a0)
	c.xor a4, s0
	c.xor a5, s1




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
