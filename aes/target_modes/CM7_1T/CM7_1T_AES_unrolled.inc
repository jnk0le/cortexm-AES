/*!
 * \file CM7_1T_AES_common.inc
 * \brief common sequences for unrolling, optimized for cortex-m7
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

//common stuff for unrolling etc.

.syntax unified
.thumb

// columns expected in r0-r3
// Te2 expected in r14
// pointer to expanded key expected in r12

// output columns in r0-r3

// 16 offset needed if r12 points to ctr+key

.macro CM7_1T_unrolled_enc_round_n round_nr, offset=0
	// start from col 1
	uxtb.w r5, r3, ror #16
lsrs.w r4, r0, #24

uxtb.w r6, r1
	ldr.w r10, [r14, r4, lsl #2]

	//current alloctaion
	// r0 - s00 | s10 | s20 |
	// r1 -     | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 |     | s33
	// r4 -
	// r5 - s23 // c1
	// r6 - s01 // c1 ror16
	// r7 -
	// r8 -
	// r9 -
	// r10 - s30T // c1 ror24

lsrs.w r4, r3, #24
	ldr.w r5, [r14, r5, lsl #2]

uxtb.w r7, r0
	ldr.w r9, [r14, r6, lsl #2]

	//current alloctaion
	// r0 -     | s10 | s20 |
	// r1 -     | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 |     |
	// r4 - s33 // c0 ror24
	// r5 - s23T // c1
	// r6 -
	// r7 - s00 // c0 ror16
	// r8 -
	// r9 - s01T // c1 ror16
	// r10 - s30T // c1 ror24

	uxtb r6, r2, ror #8
	ldr.w r8, [r14, r4, lsl #2]

	uxtb r4, r2, ror #16
	eor.w r5, r5, r10, ror #24

	//current alloctaion
	// r0 -     | s10 | s20 |
	// r1 -     | s11 | s21 | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s22 // c0
	// r5 - s23T ^ s30T // c1
	// r6 - s12 // c1 ror8
	// r7 - s00 // c0 ror16
	// r8 - s33T // c0 ror24
	// r9 - s01T // c1 ror16
	// r10 -

	eor.w r5, r5, r9, ror #16
	ldr.w r10, [r14, r7, lsl #2]

	uxtb.w r9, r1, ror #8
	ldr.w r4, [r14, r4, lsl #2]

	//current alloctaion
	// r0 -     | s10 | s20 |
	// r1 -     |     | s21 | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s22T // c0
	// r5 - s23T ^ s30T ^ s01T // c1
	// r6 - s12 // c1 ror8
	// r7 -
	// r8 - s33T // c0 ror24
	// r9 - s11 // c0 ror8
	// r10 - s00T // c0 ror16

	uxtb.w r7, r0, ror #16
	ldr.w r6, [r14, r6, lsl #2]

	eor.w r4, r4, r10, ror #16
	ldr.w r9, [r14, r9, lsl #2]

	//current alloctaion
	// r0 -     | s10 |     |
	// r1 -     |     | s21 | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s22T ^ s00T // c0
	// r5 - s23T ^ s30T ^ s01T // c1
	// r6 - s12T // c1 ror8
	// r7 - s20 // c2
	// r8 - s33T // c0 ror24
	// r9 - s11T // c0 ror8
	// r10 -

	eor.w r5, r5, r6, ror #8
	ldr.w r10, [r14, r7, lsl #2]

	uxtb.w r0, r0, ror #8
	eor.w r4, r4, r8, ror #24

	//current alloctaion
	// r0 - s10 // c3 ror8
	// r1 -     |     | s21 | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s22T ^ s00T ^ s33T // c0
	// r5 - col 1
	// r6 -
	// r7 -
	// r8 -
	// r9 - s11T // c0 ror8
	// r10 - s20T // c2

uxtb.w r7, r2
	eor.w r4, r4, r9, ror #8

lsrs.w r6, r1, #24
	ldr.w r9, [r14, r0, lsl #2]

	//current alloctaion
	// r0 -
	// r1 -     |     | s21 |
	// r2 -     |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - col 0
	// r5 - col 1
	// r6 - s31 // c2 ror24
	// r7 - s02 // c2 ror16
	// r8 -
	// r9 - s10T // c3 ror8
	// r10 - s20T // c2

	uxtb.w r8, r3, ror #8
	ldr.w r7, [r14, r7, lsl #2]

	uxtb.w r1, r1, ror #16
	ldr.w r6, [r14, r6, lsl #2]

	//current alloctaion
	// r0 -
	// r1 - s21 // c3
	// r2 -     |     |     | s32
	// r3 - s03 |     |     |
	// r4 - col 0
	// r5 - col 1
	// r6 - s31T // c2 ror24
	// r7 - s02T // c2 ror16
	// r8 - s13 // c2 ror8
	// r9 - s10T // c3 ror8
	// r10 - s20T // c2

lsrs.w r2, #24
	ldr.w r8, [r14, r8, lsl #2]

uxtb.w r3, r3
	eor.w r6, r10, r6, ror #24

	//current alloctaion
	// r0 -
	// r1 - s21 // c3
	// r2 - s32 // c3 ror24
	// r3 - s03 // c3 ror16
	// r4 - col 0
	// r5 - col 1
	// r6 - s20T ^ s31T // c2
	// r7 - s02T // c2 ror16
	// r8 - s13T // c2 ror8
	// r9 - s10T // c3 ror8
	// r10 -

	eor.w r6, r6, r7, ror #16
	ldr.w r10, [r14, r1, lsl #2]

	eor.w r6, r6, r8, ror #8
	ldr.w r7, [r14, r2, lsl #2]

	//current alloctaion
	// r0 -
	// r1 -
	// r2 -
	// r3 - s03 // c3 ror16
	// r4 - col 0
	// r5 - col 1
	// r6 - col 2
	// r7 - s32T // c3 ror24
	// r8 -
	// r9 - s10T // c3 ror8
	// r10 - s21T // c3

	eor.w r10, r10, r9, ror #8
	ldr.w r8, [r14, r3, lsl #2]

	//ldmia r12, {r0-r3}
ldrd r0,r1, [r12, #\round_nr*16 + \offset + 0]
ldrd r2,r3, [r12, #\round_nr*16 + \offset + 8]

	//current alloctaion
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 - col 0
	// r5 - col 1
	// r6 - col 2
	// r7 - s32T // c3 ror24
	// r8 - s03T // c3 ror16
	// r9 -
	// r10 - s21T ^ s10T // c3

	eor.w r7, r10, r7, ror #24
eor.w r0, r4

	eor.w r7, r7, r8, ror #16
eor.w r1, r5

eor.w r2, r6
eor.w r3, r7


.endm
