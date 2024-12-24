/*!
 * \file CM85_d4T_alt6_AES_encrypt.S
 * \brief
 *
 * not optimized yet
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// same as alt5 but not extracting in scalar

#if __ARM_EABI__ && __thumb2__ && (__ARM_FEATURE_MVE & 0b01)
.syntax unified
.thumb
.text

.balign 8
// void CM85_d4T_alt6_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM85_d4T_alt6_AES_encrypt
.type   CM85_d4T_alt6_AES_encrypt,%function
CM85_d4T_alt6_AES_encrypt:
	push {r2,r4-r11,lr} //stack out
	vpush {s16-s31}


	movw r12, #:lower16:AES_d4Te
	movt r12, #:upper16:AES_d4Te


	vldrb.u8 q0, [r0], #16 // rk
	vldrb.u8 q1, [r1] // in
	veor q0, q0, q1

	movs r1, #4
	add r1, r1, #0x000C0000 // finish offset for odd rows

	subs r3, #1 // one less
	dls lr, r3 // no skipping

	movs r3, #8

	// state and vector elements will be represented with big endian representation
	// (as in transposed canonical state representation)

	// global allocation
	// r0 - rk
	// r1 - [ 4 12 ] (int16)
	// r2 - out_p
	// r3 - 8
	// r4 -
	// r5 -
	// r12 - AES_d4Te
	// r14 - hwloop

	// q4
	// q5 -
	// q6 -
	// q7 -

	// row  []  0     1     2     3  []  0     1     2     3  []  0     1     2     3  []  0     1     2     3  []
	// column            0                        1                        2                        3
	// q0 - [] s00 | s10 | s20 | s30 [] s01 | s11 | s21 | s31 [] s02 | s12 | s22 | s32 [] s03 | s13 | s23 | s33 []
	//final []  s00T^s11T^s22T^s33T  []  s01T^s12T^s23T^s30T  []  s02T^s13T^s20T^s31T  []  s03T^s10T^s21T^s32T  []

.balign 8
1:
	// current allocation
	// q0 - [] s00 | s10 | s20 | s30 [] s01 | s11 | s21 | s31 [] s02 | s12 | s22 | s32 [] s03 | s13 | s23 | s33 []

	vshllb.u8 q1, q0, #4 // even rows
	mov.n r11, r11

	mov.n r10, r10
	vldrw.u32 q3, [r0], #16 // rk

	// ldrs cycle faster if vand reg-reg // but there is excess of vector insn anyway
	vmovlb.u16 q2, q1
	//mov.n r11, r11

	// current allocation
	// r4 -
	// r5 -
	// r6 -
	// r7 -
	// r8 -
	// r9 -
	// r10 -
	// r11 -
	// q0 - []  -  | s10 |  -  | s30 []  -  | s11 |  -  | s31 []  -  | s12 |  -  | s32 []  -  | s13 |  -  | s33 []
	// q1 - []  -  | s20 []  -  | s21 []  -  | s22 []  -  | s23 []
	// q2 - [] s00 [] s01 [] s02 [] s03 []
	// q3 - rk
	// q4 -
	// q5 -
	// q6 -
	// q7 -



	vmov.64 r4,r5, d4
	mov.n r11, r11

	vmov.64 r6,r7, d5
	mov.n r11, r11 // ex3

	vmovlt.u16 q2, q1
	mov.n r11, r11 // ex2

	// current allocation
	// r4 - s00
	// r5 - s01
	// r6 - s02
	// r7 - s03
	// r8 -
	// r9 -
	// r10 -
	// r11 -
	// q0 - []  -  | s10 |  -  | s30 []  -  | s11 |  -  | s31 []  -  | s12 |  -  | s32 []  -  | s13 |  -  | s33 []
	// q1 -
	// q2 - [] s20 [] s21 [] s22 [] s23 []
	// q3 - rk
	// q4 -
	// q5 -
	// q6 -
	// q7 -



vorr.i32 q2, #0x8
mov.n r11, r11

	vmov.64 r8,r9, d4
	ldr r4, [r12, r4]

	vmov.64 r10,r11, d5
	ldr r5, [r12, r5]

	vshllt.u8 q0, q0, #4
	ldr r6, [r12, r6]

	// current allocation
	// r4 - s00T
	// r5 - s01T
	// r6 - s02T
	// r7 - s03
	// r8 - s20
	// r9 - s21
	// r10 - s22
	// r11 - s23
	// q0 - [] s10 | s30 [] s11 | s31 [] s12 | s32 [] s13 | s33 []
	// q1 -
	// q2 -
	// q3 - rk
	// q4 -
	// q5 -
	// q6 -
	// q7 -

	vmov.64 d2, r4,r5
	ldr r7, [r12, r7]

	vmov.64 d3, r6,r7
	ldr r10, [r12, r10]

	vadd.i32 q0, q0, r1 // [ 4 12 4 12 4 12 4 12] // indices won't carry across 16 bit
	ldr r11, [r12, r11]

	// current allocation
	// r4 -
	// r5 -
	// r6 -
	// r7 -
	// r8 - s20
	// r9 - s21
	// r10 - s22T
	// r11 - s23T
	// q0 - [] s10 | s30 [] s11 | s31 [] s12 | s32 [] s13 | s33 []
	// q1 - [] s00T [] s01T [] s02T [] s03T []
	// q2 -
	// q3 - rk
	// q4 -
	// q5 -
	// q6 -
	// q7 -

	veor q3, q3, q1
	ldr r8, [r12, r8]

	vmovlb.u16 q1, q0
	ldr r9, [r12, r9]

	vmov.64 r4,r5, d2
	mov.n r11, r11 // -

	// current allocation
	// r4 - s10
	// r5 - s11
	// r6 -
	// r7 -
	// r8 - s20T
	// r9 - s21T
	// r10 - s22T
	// r11 - s23T
	// q0 - []  -  | s30 []  -  | s31 []  -  | s32 []  -  | s33 []
	// q1 - []  -  []  -  [] s12 [] s13 []
	// q2 -
	// q3 - [] s00T [] s01T [] s02T [] s03T [] ^ rk
	// q4 -
	// q5 -
	// q6 -
	// q7 -

	vmov.64 r6,r7, d3
	mov.n r11, r11 // EX3

	vmov.64 d4, r10,r11
	mov.n r11, r11 // EX2

	vmov.64 d5, r8,r9
	ldr r5, [r12, r5] // EX1

	// current allocation
	// r4 - s10
	// r5 - s11T
	// r6 - s12
	// r7 - s13
	// r8 -
	// r9 -
	// r10 -
	// r11 -
	// q0 - []  -  | s30 []  -  | s31 []  -  | s32 []  -  | s33 []
	// q1 -
	// q2 - [] s22T [] s23T [] s20T [] s21T []
	// q3 - [] s00T [] s01T [] s02T [] s03T [] ^ rk
	// q4 -
	// q5 -
	// q6 -
	// q7 -

	vmovlt.u16 q0, q0
	ldr r6, [r12, r6]

	vmov.64 r8,r9, d0
	ldr r7, [r12, r7]

	vmov.64 r10,r11, d1
	ldr r4, [r12, r4]

	// current allocation
	// r4 - s10T
	// r5 - s11T
	// r6 - s12T
	// r7 - s13T
	// r8 - s30
	// r9 - s31
	// r10 - s32
	// r11 - s33
	// q0 -
	// q1 -
	// q2 - [] s22T [] s23T [] s20T [] s21T []
	// q3 - [] s00T [] s01T [] s02T [] s03T [] ^ rk
	// q4 -
	// q5 -
	// q6 -
	// q7 -

	vmov d0, r5,r6
	mov.n r10, r10 // ??

	vmov d1, r7,r4
	ldr r8, [r12, r8] // r8/r9 EX1

	veor q3, q3, q2
	ldr r11, [r12, r11] // r10/r11 EX1

	// current allocation
	// r4 -
	// r5 -
	// r6 -
	// r7 -
	// r8 - s30T
	// r9 - s31
	// r10 - s32
	// r11 - s33T
	// q0 - [] s11T [] s12T [] s13T [] s10T []
	// q1 -
	// q2 -
	// q3 - [] s00T^s22T [] s01T^s23T [] s02T^s20T [] s03T^s21T [] ^ rk
	// q4 -
	// q5 -
	// q6 -
	// q7 -

	veor q0, q0, q3
	ldr r9, [r12, r9]


	vmov.64 d2, r11,r8
	ldr r10, [r12, r10]


	vmov.64 d3, r9,r10
	mov.n r11, r11


	veor q0, q0, q1
	mov.n r11, r11


	le lr, 1b

	// 29 cycles per round
	// 27 with ofsset from 4 pointers instead of vorr/vadd
	// eors in scalar ?

	// copypaste from CM7_1T
	//not optimizing now, need rounds first
	movw r14, #:lower16:AES_Te2
	movt r14, #:upper16:AES_Te2
	mov r12, r0
	vmov r0,r2, q0[2], q0[0]
	vmov r1,r3, q0[3], q0[1]

	uxtb r6, r3, ror #16 // row 2 col 1
	lsrs.w r7, r0, #24 // row 3 col 1 // cant .n
	uxtb r5, r2, ror #8 // row 1 col 1
	ldrb.w r8, [r14, r7, lsl #2]
	uxtb.w r4, r1 // row 0 col 1 // cant .n
	ldrb.w r6, [r14, r6, lsl #2]
	lsrs.w r7, r3, #24 // row 3 col 0 // cant .n
	ldrb.w r5, [r14, r5, lsl #2]
	//current alloctaion
	// r0 - s00 | s10 | s20 |
	// r1 -     | s11 | s21 | s31
	// r2 - s02 |     | s22 | s32
	// r3 - s03 | s13 |     |
	// r4 - s01  //r0c1
	// r5 - s12` //r1c1
	// r6 - s23` //r2c1
	// r7 - s33  //r3c0
	// r8 - s30` //r3c1
	// r9 -
	// r10 -
	// r11 -
	orr.w r11, r6, r8, lsl #8 // col 1 upper part
	ldrb.w r9, [r14, r4, lsl #2]
	uxtb r6, r2, ror #16 // row 2 col 0
	ldrb.w r8, [r14, r7, lsl #2]
	//current alloctaion
	// r0 - s00 | s10 | s20 |
	// r1 -     | s11 | s21 | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 -
	// r5 - s12` //r1c1
	// r6 - s22  //r2c0
	// r7 -
	// r8 - s33` //r3c0
	// r9 - s01` //r0c1
	// r10 -
	// r11 - s23` | s30` //c1 upper
	uxtb.w r7, r0 // row 0 col 0 // cant .n
	orr.w r10, r9, r5, lsl #8 // col 1 bottom part
	uxtb r4, r1, ror #8 // row 1 col 0
	ldrb.w r6, [r14, r6, lsl #2]
	//current alloctaion
	// r0 -     | s10 | s20 |
	// r1 -     |     | s21 | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s11  //r1c0
	// r5 -
	// r6 - s22` //r2c0
	// r7 - s00  //r0c0
	// r8 - s33` //r3c0
	// r9 -
	// r10 - s01` | s12` //c1 bottom
	// r11 - s23` | s30` //c1 upper
	uxtb r5, r0, ror #16 // row 2 col 2
	ldrb.w r9, [r14, r7, lsl #2]
	orr.w r8, r6, r8, lsl #8 // col 0 upper part
	ldrb.w r4, [r14, r4, lsl #2]
	//current alloctaion
	// r0 -     | s10 |     |
	// r1 -     |     | s21 | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s11` //r1c0
	// r5 - s20  //r2c2
	// r6 -
	// r7 -
	// r8 - s22` | s33` //c0 upper
	// r9 - s00` //r0c0
	// r10 - s01` | s12` //c1 bottom
	// r11 - s23` | s30` //c1 upper
	uxtb r6, r2 // row 0 col 2
	lsrs r7, r1, #24 // row 3 col 2
	lsrs r2, r2, #24 // row 3 col 3
	ldrb.w r7, [r14, r7, lsl #2]
	//current alloctaion
	// r0 -     | s10 |     |
	// r1 -     |     | s21 |
	// r2 - s32  //r3c3
	// r3 - s03 | s13 |     |
	// r4 - s11` //r1c0
	// r5 - s20  //r2c2
	// r6 - s02  //r0c2
	// r7 - s31` //r3c2
	// r8 - s22` | s33` //c0 upper
	// r9 - s00` //r0c0
	// r10 - s01` | s12` //c1 bottom
	// r11 - s23` | s30` //c1 upper
	orr.w r9, r9, r4, lsl #8 // col 0 bottom part
	ldrb.w r5, [r14, r5, lsl #2]
	uxtb r4, r3, ror #8 // row 1 col 2
	ldrb.w r6, [r14, r6, lsl #2]
	//current alloctaion
	// r0 -     | s10 |     |
	// r1 -     |     | s21 |
	// r2 - s32  //r3c3
	// r3 - s03 |     |     |
	// r4 - s13  //r1c2
	// r5 - s20` //r2c2
	// r6 - s02` //r0c2
	// r7 - s31` //r3c2
	// r8 - s22` | s33` //c0 upper
	// r9 - s00` | s11` //c0 bottom
	// r10 - s01` | s12` //c1 bottom
	// r11 - s23` | s30` //c1 upper
	uxtb r3, r3 // row 0 col 3
	orr.w r7, r5, r7, lsl #8  // col 2 upper part
	uxtb r1, r1, ror #16 // row 2 col 3
	ldrb.w r4, [r14, r4, lsl #2]
	//current alloctaion
	// r0 -     | s10 |     |
	// r1 - s21  //r2c3
	// r2 - s32  //r3c3
	// r3 - s03  //r0c3
	// r4 - s13` //r1c2
	// r5 -
	// r6 - s02` //r0c2
	// r7 - s20` | s31` //c2 upper
	// r8 - s22` | s33` //c0 upper
	// r9 - s00` | s11` //c0 bottom
	// r10 - s01` | s12` //c1 bottom
	// r11 - s23` | s30` //c1 upper
	uxtb r0, r0, ror #8 // row 1 col 3
	ldrb.w r2, [r14, r2, lsl #2]
	orr.w r5, r9, r8, lsl #16 // col 0
	ldrb.w r1, [r14, r1, lsl #2]
	//current alloctaion
	// r0 - s10  //r1c3
	// r1 - s21` //r2c3
	// r2 - s32` //r3c3
	// r3 - s03  //r0c3
	// r4 - s13` //r1c2
	// r5 - col 0
	// r6 - s02` //r0c2
	// r7 - s20` | s31` //c2 upper
	// r8 -
	// r9 -
	// r10 - s01` | s12` //c1 bottom
	// r11 - s23` | s30` //c1 upper
	orr.w r4, r6, r4, lsl #8 // c2 bottom
	ldrb.w r0, [r14, r0, lsl #2]
	orr.w r8, r1, r2, lsl #8 // col 3 upper part
	ldrb.w r3, [r14, r3, lsl #2]
	//current alloctaion
	// r0 - s10` //r1c3
	// r1 -
	// r2 -
	// r3 - s03` //r0c3
	// r4 - s02` | s13` //c2 bottom
	// r5 - col 0
	// r6 -
	// r7 - s20` | s31` //c2 upper
	// r8 - s21` | s32` //c3 upper
	// r9 -
	// r10 - s01` | s12` //c1 bottom
	// r11 - s23` | s30` //c1 upper
	orr.w r7, r4, r7, lsl #16 // col 2
	nop
	orr.w r9, r3, r0, lsl #8 // col 3 bottom part
	ldr r6, [sp, #64] // load output pointer, ignore stack opt
	ldm r12, {r0-r3}
	//current alloctaion
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 - unstacked
	// r5 - col 0
	// r6 - out p
	// r7 - col 2
	// r8 - s21` | s32` //c3 upper
	// r9 - s03` | s10` //c3 bottom
	// r10 - s01` | s12` //c1 bottom
	// r11 - s23` | s30` //c1 upper
	eors r0, r5
	orr.w r5, r10, r11, lsl #16 // col 1
	eors r1, r5
	orr.w r5, r9, r8, lsl #16 // col 3
	eors r2, r7
	eors r3, r5
	stmia r6!, {r0-r3}

	vpop {s16-s31}
	pop {r2,r4-r11,pc}


#endif
