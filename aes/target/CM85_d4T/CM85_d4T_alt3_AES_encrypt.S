/*!
 * \file CM85_d4T_alt3_AES_encrypt.S
 * \brief
 *
 * not optimized yet
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// 3rd alternative version of d4T, vloating point moves instead of scatter/gather

// compile for compatible targets only
#if __ARM_EABI__ && __thumb2__ && (__ARM_FEATURE_MVE & 0b01)

.syntax unified
.thumb
.text

.balign 8
// void CM85_d4T_alt3_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM85_d4T_alt3_AES_encrypt
.type   CM85_d4T_alt3_AES_encrypt,%function
CM85_d4T_alt3_AES_encrypt:
	push {r2,r4-r11,lr} //stack out
	vpush {s16-s31}

	movw r12, #:lower16:AES_d4Te
	movt r12, #:upper16:AES_d4Te

	vldrb.u8 q0, [r0], #16 // rk
	vldrb.u8 q1, [r1] // in

	veor q0, q0, q1


	// offsets for odd rows, even rows are don inline
	vmov.i32 q7, #0x000C0000
	vorr.i32 q7, #0x00000004

	// state and vector elements will be represented with the big endian representation
	// (as in transposed canonical state representation)

	// global allocation
	// r0 - rk
	// r12 - AES_d4Te
	// r14 - hwloop
	// q3 -
	// q4 -
	// q5 -
	// q6 -
	// q7 - [ 4 12 4 12 4 12 4 12]

	// row  []  0     1     2     3  []  0     1     2     3  []  0     1     2     3  []  0     1     2     3  []
	// column            0                        1                        2                        3
	// q0 - [] s00 | s10 | s20 | s30 [] s01 | s11 | s21 | s31 [] s02 | s12 | s22 | s32 [] s03 | s13 | s23 | s33 []
	//final []  s00T^s11T^s22T^s33T  []  s01T^s12T^s23T^s30T  []  s02T^s13T^s20T^s31T  []  s03T^s10T^s21T^s32T  []


	subs r3, #1 // one less
	dls lr, r3 // no skipping
.balign 8
1:
	// prepare for gathers
	vshllt.u8 q1, q0, #4
	vshllb.u8 q0, q0, #4

	// add offsets into diffusion
	vorr.i32 q0, #0x00080000 // [ 0 8 0 8 0 8 0 8 ]
	vorr q1, q1, q7 // immediate is out of range

	// current allocation
	// q0 - [] s00 | s20 [] s01 | s21 [] s02 | s22 [] s03 | s23 []
	// q1 - [] s10 | s30 [] s11 | s31 [] s12 | s32 [] s13 | s33 []

	// there is no widening addition

	vmovlb.u16 q2, q0
	vmovlt.u16 q3, q0
	vmovlb.u16 q4, q1
	vmovlt.u16 q5, q1

	// current allocation
	// s0:s7 -

	// s8 - s00 // ok
	// s9 - s01
	// s10 - s02
	// s11 - s03

	// s12 - s20
	// s13 - s21
	// s14 - s22
	// s15 - s23

	// s16 - s10
	// s17 - s11
	// s18 - s12
	// s19 - s13

	// s20 - s30
	// s21 - s31
	// s22 - s32
	// s23 - s33


	// required layout:
	// q2 - [] s00 [] s12 [] s20 [] s32 []
	// q0 - [] s11 [] s23 [] s31 [] s03 []
	// q1 - [] s22 [] s30 [] s02 [] s10 []
	// q3 - [] s33 [] s01 [] s13 [] s21 []

	// 15 total moves

	// vmovx + vsel ??
	// mov 2 regs ??
	// half prec alu places zoros in top

	// only if mve_f available ?
	// FPSCR.FZ16 not used?

	vmov.f32 s0, s17
	vmov.f32 s1, s15
	vmov.f32 s2, s21
	vmov.f32 s3, s11

	vmov.f32 s4, s14
	vmov.f32 s5, s20
	vmov.f32 s6, s10
	vmov.f32 s7, s16

	// current allocation
	// s0 - s11
	// s1 - s23
	// s2 - s31
	// s3 - s03

	// s4 - s22
	// s5 - s30
	// s6 - s02
	// s7 - s10

	// s8 - s00 // ok
	// s9 - s01
	// s10 -
	// s11 -

	// s12 - s20
	// s13 - s21
	// s14 -
	// s15 -

	// s16 -
	// s17 -
	// s18 - s12
	// s19 - s13

	// s20 -
	// s21 -
	// s22 - s32
	// s23 - s33

	vmov.f32 s10, s12
	vmov.f32 s11, s22

	vmov.f32 s15, s13
	vmov.f32 s13, s9

	vmov.f32 s9, s18
	vmov.f32 s12, s23
	vmov.f32 s14, s19

	// current allocation
	// s0 - s11
	// s1 - s23
	// s2 - s31
	// s3 - s03

	// s4 - s22
	// s5 - s30
	// s6 - s02
	// s7 - s10

	// s8 - s00
	// s9 - s12
	// s10 - s20
	// s11 - s32

	// s12 - s33
	// s13 - s01
	// s14 - s13
	// s15 - s21

	// s16:s23 -

	// q2 - [] s00 [] s12 [] s20 [] s32 []
	// q0 - [] s11 [] s23 [] s31 [] s03 []
	// q1 - [] s22 [] s30 [] s02 [] s10 []
	// q3 - [] s33 [] s01 [] s13 [] s21 []


	vldrw.u32 q5, [r12, q0] // 2 cycles
	vldrw.u32 q4, [r12, q1] // 2 cycles
	vldrw.u32 q0, [r12, q2] // 2 cycles
	vldrw.u32 q1, [r12, q3] // 2 cycles

	veor q0, q0, q1
	veor q0, q0, q5
	veor q0, q0, q4

	//apply rk
	vldrw.u32 q1, [r0], #16
	veor q0, q0, q1

	le lr, 1b

	// 17 vector insns (21 vector cycles), 15 scalar fp moves (f16 "moves" will cut 4 vector insn and add 1 scalar move)


	// final round

	movw r14, #:lower16:AES_Te2
	movt r14, #:upper16:AES_Te2

	mov r12, r0

	vmov r0,r2, q0[2], q0[0]
	vmov r1,r3, q0[3], q0[1]

	// copypaste from CM7_1T
	//not optimizing now, need rounds first

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
