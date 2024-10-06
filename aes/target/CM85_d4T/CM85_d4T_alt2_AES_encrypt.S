/*!
 * \file CM85_d4T_alt2_AES_encrypt.S
 * \brief
 *
 * not optimized yet
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// second alternative version of d4T, do indexes before scatter

// compile for compatible targets only
#if __ARM_EABI__ && __thumb2__ && (__ARM_FEATURE_MVE & 0b01)

.syntax unified
.thumb
.text

.balign 16
shiftrows_d4T_scatter_perm:
	//.byte 0, 11, 2, 9, 13, 4, 15, 6, 10, 1, 8, 3, 7, 14, 5, 12

	// precomputed oeven/odd, 2 loads instead of 1 load + 2 shifts, but prologue might have enough loads/stores
	// leftshift can also be done by scatters
	//.short 2*0, 2*2, 2*13, 2*15, 2*10, 2*8, 2*7, 2*5
	//.short 2*11, 2*9, 2*4, 2*6, 2*1, 2*3, 2*14, 2*12

	// widen by loads, apply shift in scatters or here??
	.byte 0, 2, 13, 15, 10, 8, 7, 5
	.byte 11, 9, 4, 6, 1, 3, 14, 12

// void CM85_d4T_alt2_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM85_d4T_alt2_AES_encrypt
.type   CM85_d4T_alt2_AES_encrypt,%function
CM85_d4T_alt2_AES_encrypt:
	push {r2,r4-r11,lr} //stack out
	vpush {s16-s31}

	movw r12, #:lower16:AES_d4Te
	movt r12, #:upper16:AES_d4Te

	vldrb.u8 q0, [r0], #16 // rk
	vldrb.u8 q1, [r1] // in

	veor q0, q0, q1

	subs sp, #32 // scatter area
	adr r4, shiftrows_d4T_scatter_perm // cant vector load by pc
	vldrb.u16 q4, [r4, #0]
	vldrb.u16 q5, [r4, #8]
	mov r4, sp // can't do widening loads by high reg

	vmov.i32 q6, #0x00080000 // prepare offsets for even rows

	movs r2, #4
	vadd.i16 q7, q6, r2

	// state and vector elements will be represented with the big endian representation
	// (transposed canonical state representation)

	// global allocation
	// r0 - rk
	// r4 - sp (due to widening loads)
	// r12 - AES_d4Te
	// r14 - hwloop
	// q3 -
	// q4 - [ 0, 2, 13, 15, 10, 8, 7, 5 ] * 2 : shiftrows_d4T_scatter_perm (even half)
	// q5 - [ 11, 9, 4, 6, 1, 3, 14, 12 ] * 2 : shiftrows_d4T_scatter_perm (odd half)
	// q6 - [ 0 8 0 8 0 8 0 8 ]
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

	vadd.i16 q0, q0, q6
	vadd.i16 q1, q1, q7

	// current allocation
	// q0 - [] s00 | s20 [] s01 | s21 [] s02 | s22 [] s03 | s23 []
	// q1 - [] s10 | s30 [] s11 | s31 [] s12 | s32 [] s13 | s33 []

	vstrh.16 q0, [r4, q4, uxtw #1] // 4 cycles
	vstrh.16 q1, [r4, q5, uxtw #1] // 4 cycles

	// in memory layout:
	// sp + 0  : s00, s12, s20, s32
	// sp + 8  : s11, s23, s31, s03
	// sp + 16 : s22, s30, s02, s10
	// sp + 24 : s33, s01, s13, s21

	vldrh.u32 q1, [r4, #0]
	vldrh.u32 q2, [r4, #8]
	vldrh.u32 q3, [r4, #16]

	vldrw.u32 q0, [r12, q1] // 2 cycles
	vldrw.u32 q1, [r12, q2] // 2 cycles
	vldrw.u32 q2, [r12, q3] // 2 cycles

	veor q0, q0, q1
	veor q0, q0, q2

	vldrh.u32 q3, [r4, #24]
	vldrw.u32 q2, [r12, q3] // 2 cycles
	veor q0, q0, q2

	//apply rk
	vldrw.u32 q1, [r0], #16
	veor q0, q0, q1

	le lr, 1b

	// 19 insns total, theoretical 29 cycles, it's load intense in second part (loads after pipelineable loads)
	// store then gather would be more efficient with same theoretical cycles at higher register pressure


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
	ldr r6, [sp, #64+32] // load output pointer, ignore stack opt

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

	add sp, #32 // scatter area

	vpop {s16-s31}
	pop {r2,r4-r11,pc}

#endif
