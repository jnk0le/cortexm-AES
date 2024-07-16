/*!
 * \file CM3_1T_AES_common.inc
 * \brief
 *
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

.macro CM3_1T_unrolled_enc_round
	uxtb r4, r0
	lsrs r6, r3, #24
	uxtb.w r9, r1, ror #8
	uxtb.w r10, r2, ror #16
	uxtb.w r8, r3, ror #16
	uxtb r5, r1
	lsrs r7, r0, #24

	ldr.w r4, [r14, r4, lsl #2]
	ldr.w r6, [r14, r6, lsl #2]
	ldr.w r9, [r14, r9, lsl #2]
	ldr.w r10, [r14, r10, lsl #2]
	ldr.w r8, [r14, r8, lsl #2]
	ldr.w r5, [r14, r5, lsl #2]
	ldr.w r7, [r14, r7, lsl #2]

	//current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00T // c0 ror16
	// r5 - s01T // c1 ror16
	// r6 - s33T // c0 ror24
	// r7 - s30T // c1 ror24
	// r8 - s23T // c1 ror0
	// r9 - s11T // c0 ror8
	// r10 - s22T // c0 ror0

	eor.w r4, r10, r4, ror #16
	eor.w r4, r4, r9, ror #8
	eor.w r4, r4, r6, ror #24
	eor.w r5, r8, r5, ror #16
	eor.w r5, r5, r7, ror #24

	uxtb r6, r2
	uxtb r7, r3
	uxtb.w r8, r0, ror #16
	uxtb.w r9, r2, ror #8
	uxtb.w r10, r1, ror #16
	uxtb.w r3, r3, ror #8
	uxtb.w r0, r0, ror #8
	lsrs r1, r1, #24
	lsrs r2, r2, #24

	ldr.w r6, [r14, r6, lsl #2]
	ldr.w r7, [r14, r7, lsl #2]
	ldr.w r8, [r14, r8, lsl #2]
	ldr.w r9, [r14, r9, lsl #2]
	ldr.w r10, [r14, r10, lsl #2]
	ldr.w r3, [r14, r3, lsl #2]
	ldr.w r0, [r14, r0, lsl #2]
	ldr.w r1, [r14, r1, lsl #2]
	ldr.w r2, [r14, r2, lsl #2]

	//current allocation
	// r0 - s10T // c3 ror8
	// r1 - s31T // c2 ror24
	// r2 - s32T // c2 ror24
	// r3 - s13T // c2 ror8
	// r4 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r5 - s01T ^ s23T ^ s30T // c1
	// r6 - s02T // c2 ror16
	// r7 - s03T // c3 ror16
	// r8 - s20T // c2 ror0
	// r9 - s12T // c1 ror8
	// r10 - s21T // c3 ror0

	eor.w r5, r5, r9, ror #8
	eor.w r6, r8, r6, ror #16
	eor.w r7, r10, r7, ror #16
	eor.w r6, r6, r3, ror #8
	eor.w r7, r7, r0, ror #8
	eor.w r6, r6, r1, ror #24
	eor.w r7, r7, r2, ror #24

	ldmia.w r12!, {r0-r3} // load rk

	//current allocation
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r5 - s01T ^ s12T ^ s23T ^ s30T // c1
	// r6 - s02T ^ s13T ^ s20T ^ s31T // c2
	// r7 - s03T ^ s10T ^ s21T ^ s32T // c3
	// r8 -
	// r9 -
	// r10 -

	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7
.endm

// columns expected in r0-r3
// Te2 expected in r14
// pointer to end-16 of expanded key expected in r12

// output columns in r0-r3

.macro CM3_1T_unrolled_dec_round
	uxtb r4, r0
	lsrs r6, r1, #24
	uxtb.w r9, r3, ror #8
	uxtb.w r10, r2, ror #16
	uxtb.w r8, r3, ror #16
	uxtb r5, r1
	lsrs r7, r2, #24

	ldr.w r4, [r14, r4, lsl #2]
	ldr.w r6, [r14, r6, lsl #2]
	ldr.w r9, [r14, r9, lsl #2]
	ldr.w r10, [r14, r10, lsl #2]
	ldr.w r8, [r14, r8, lsl #2]
	ldr.w r5, [r14, r5, lsl #2]
	ldr.w r7, [r14, r7, lsl #2]

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 -  -  | s11 | s21 |  -
	// r2 - s02 | s12 |  -  |  -
	// r3 - s03 |  -  |  -  | s33
	// r4 - s00T // c0 ror16
	// r5 - s01T // c1 ror16
	// r6 - s31T // c0 ror24
	// r7 - s32T // c1 ror24
	// r8 - s23T // c1 ror0
	// r9 - s13T // c0 ror8
	// r10 - s22T // c0 ror0

	eor.w r4, r10, r4, ror #16
	eor.w r4, r4, r9, ror #8
	eor.w r4, r4, r6, ror #24
	eor.w r5, r8, r5, ror #16
	eor.w r5, r5, r7, ror #24

	uxtb r6, r2
	uxtb r7, r3
	uxtb.w r8, r0, ror #16
	uxtb.w r9, r0, ror #8
	uxtb.w r10, r1, ror #16
	uxtb.w r1, r1, ror #8
	uxtb.w r2, r2, ror #8
	lsrs r3, r3, #24
	lsrs r0, r0, #24

	ldr.w r6, [r14, r6, lsl #2]
	ldr.w r7, [r14, r7, lsl #2]
	ldr.w r8, [r14, r8, lsl #2]
	ldr.w r9, [r14, r9, lsl #2]
	ldr.w r10, [r14, r10, lsl #2]
	ldr.w r1, [r14, r1, lsl #2]
	ldr.w r2, [r14, r2, lsl #2]
	ldr.w r3, [r14, r3, lsl #2]
	ldr.w r0, [r14, r0, lsl #2]

	//current allocation
	// r0 - s30T // c3 ror24
	// r1 - s11T // c2 ror8
	// r2 - s12T // c3 ror8
	// r3 - s33T // c2 ror24
	// r4 - s00T ^ s13T ^ s22T ^ s31T // c0
	// r5 - s01T ^ s23T ^ s32T // c1
	// r6 - s02T // c2 ror16
	// r7 - s03T // c3 ror16
	// r8 - s20T // c2 ror0
	// r9 - s10T // c1 ror8
	// r10 - s21T // c3 ror0

	eor.w r5, r5, r9, ror #8
	eor.w r6, r8, r6, ror #16
	eor.w r7, r10, r7, ror #16
	eor.w r6, r6, r1, ror #8
	eor.w r7, r7, r2, ror #8
	eor.w r6, r6, r3, ror #24
	eor.w r7, r7, r0, ror #24

	ldmdb r12!, {r0-r3} // laod rk

	//current allocation
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 - s00T ^ s13T ^ s22T ^ s31T // c0
	// r5 - s01T ^ s10T ^ s23T ^ s32T // c1
	// r6 - s02T ^ s11T ^ s20T ^ s33T // c2
	// r7 - s03T ^ s12T ^ s21T ^ s30T // c3
	// r8 -
	// r9 -
	// r10 -

	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7
.endm


// columns expected in r4-r7
// Te2 expected in r14
// pointer to expanded key expected in r12

// output columns in r4-r7

.macro CM3_1T_unrolled_enc_round_n round_nr, offset=0
	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r8, [r12, #\round_nr*16 + \offset + 0]
	ldr r9, [r12, #\round_nr*16 + \offset + 4]
	ldr r10, [r12, #\round_nr*16 + \offset + 8]
	ldr r11, [r12, #\round_nr*16 + \offset + 12]
	eor r8, r8, r0, ror #16
	eor r9, r9, r1, ror #16
	eor r10, r10, r2, ror #16
	eor r11, r11, r3, ror #16

	uxtb r0, r5, ror #8
	uxtb r1, r6, ror #8
	uxtb r2, r7, ror #8
	uxtb r3, r4, ror #8
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	eor r8, r8, r0, ror #8
	eor r9, r9, r1, ror #8
	eor r10, r10, r2, ror #8
	eor r11, r11, r3, ror #8

	uxtb r0, r6, ror #16
	uxtb r1, r7, ror #16
	uxtb r2, r4, ror #16
	uxtb r3, r5, ror #16

	lsrs r7, #24
	lsrs r4, #24
	lsrs r5, #24
	lsrs r6, #24

	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]

	ldr r7, [r14, r7, lsl #2]
	ldr r4, [r14, r4, lsl #2]
	ldr r5, [r14, r5, lsl #2]
	ldr r6, [r14, r6, lsl #2]

	// change xoring order to writeback r4-r7 without extra moves
	eor r0, r0, r7, ror #24
	eor r1, r1, r4, ror #24
	eor r2, r2, r5, ror #24
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1
	eor r6, r10, r2
	eor r7, r11, r3
.endm
