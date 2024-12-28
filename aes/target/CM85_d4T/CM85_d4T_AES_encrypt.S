/*!
 * \file CM85_d4T_AES_encrypt.S
 * \brief cortex-m85 optimized aes encryption
 *
 * Utilizes diffused 4 Te tables, which protects from bank timming attacks, as each
 * data dependent lookup can hit only within one bank.
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

#if __ARM_EABI__ && __thumb2__ && (__ARM_FEATURE_MVE & 0b01)
.syntax unified
.thumb
.text

.balign 16
AES_shiftrows_d4T_final_gather_perm:
	.byte 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11

	// in memory layout
	// s00, s10, s20, s30, s01, s11, s21, s31, s02, s12, s22, s32, s03, s13, s23, s33

	// final layout after merge
	// q0 - [] s00`| s11`| s22`| s33`[] s01`| s12`| s23`| s30`[] s02`| s13`| s20`| s31`[] s03`| s10`| s21`| s32`[]

	// 4 banks
	//bank1 - 0 1 2 3
	//bank2 - 4 5 6 7
	//bank3 - 8 9 10 11
	//bank4 - 12 13 14 15

	// 2 banks (each pair still accesses different bank)
	//bank1 - 0 1 2 3   8 9 10 11
	//bank2 - 4 5 6 7   12 13 14 15

.balign 8
// void CM85_d4T_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM85_d4T_AES_encrypt
.type   CM85_d4T_AES_encrypt,%function
CM85_d4T_AES_encrypt:
	strd r11,lr, [sp, #-(32+8)]! // 1 slot for padding
	movw r12, #:lower16:AES_d4Te

	strd r9,r10, [sp, #8]
	movt r12, #:upper16:AES_d4Te

	strd r7,r8, [sp, #16]
	subs r3, #1 // one less

	strd r5,r6, [sp, #24]
	dls lr, r3 // no skipping

	str r4, [sp, #32]
	vldrb.u8 q1, [r1] // in

	sub sp, #16 // area for shiftrows shuffling in final round
	vldrb.u8 q0, [r0], #16 // rk

	veor q0, q0, q1

	// state and vector elements will be represented with big endian representation
	// (as in transposed canonical state representation)

	// global allocation
	// r0 - rk
	// r1 - AES_d4Te + 4
	// r2 - out_p
	// r3 - AES_d4Te + 12

	// r12 - AES_d4Te
	// r14 - hwloop

	// row  []  0     1     2     3  []  0     1     2     3  []  0     1     2     3  []  0     1     2     3  []
	// column            0                        1                        2                        3
	// q0 - [] s00 | s10 | s20 | s30 [] s01 | s11 | s21 | s31 [] s02 | s12 | s22 | s32 [] s03 | s13 | s23 | s33 []
	//final []  s00T^s11T^s22T^s33T  []  s01T^s12T^s23T^s30T  []  s02T^s13T^s20T^s31T  []  s03T^s10T^s21T^s32T  []

	//used addressing modes
	// row 0 - r12 + x
	// row 2 - (x + r12) + 8
	// row 1/3 - r1/r3 + x

.balign 8
1:
	// current allocation
	// q0 - [] s00 | s10 | s20 | s30 [] s01 | s11 | s21 | s31 [] s02 | s12 | s22 | s32 [] s03 | s13 | s23 | s33 []

	add r1, r12, #4 // AES_d4Te + 4
	vldrw.u32 q3, [r0], #16 // rk

	vshllb.u8 q1, q0, #4 // even rows

	// current allocation
	// q0 - []  -  | s10 |  -   | s30 []  -  | s11 |  -  | s31 []  -  | s12 |  -  | s32 []  -  | s13 |  -  | s33 []
	// q1 - [] s00 | s20 [] s01 | s21 [] s02 | s22 [] s03 | s23 []
	// q2 -
	// q3 - rk

	vmov.64 r4,r5, d2 // move in asap
	add r3, r12, #12 // AES_d4Te + 12

	vmov.64 r6,r7, d3
	and.w r8, r4, #0xff0 // EX3

	vshllt.u8 q0, q0, #4 // odd rows
	and.w r9, r5, #0xff0 // EX2

	// current allocation
	// r4 -  -  | s20
	// r5 -  -  | s21
	// r6 - s02 | s22
	// r7 - s03 | s23
	// r8 - s00
	// r9 - s01
	// r10 -
	// r11 -
	// q0 - [] s10 | s30 [] s11 | s31 [] s12 | s32 [] s13 | s33 []
	// q1 -
	// q2 -
	// q3 - rk

	// can't do vector due to A port contention
	add.w r10, r12, r4, lsr #16
	add.w r11, r12, r5, lsr #16

	vmovlb.u16 q1, q0
	ldr r8, [r12, r8]

	add.w r4, r12, r6, lsr #16
	ldr r9, [r12, r9]

	// current allocation
	// r4 - s22
	// r5 -
	// r6 - s02 |  -
	// r7 - s03 | s23
	// r8 - s00T
	// r9 - s01T
	// r10 - s20
	// r11 - s21
	// q0 - []  -  | s30 []  -  | s31 []  -  | s32 []  -  | s33 []
	// q1 - [] s10 [] s11 [] s12 [] s13 []
	// q2 -
	// q3 - rk

	vmovlt.u16 q0, q0
	ldr r10, [r10, #8]

	vmov.64 d4, r8,r9
	ldr r11, [r11, #8]

	vmov.64 d5, r10,r11
	add.w r5, r12, r7, lsr #16

	// current allocation
	// r4 - s22
	// r5 - s23
	// r6 - s02 |  -
	// r7 - s03 |  -
	// r8 -
	// r9 -
	// r10 -
	// r11 -
	// q0 - [] s30 [] s31 [] s32 [] s33 []
	// q1 - [] s10 [] s11 [] s12 [] s13 []
	// q2 - [] s00T [] s01T [] s20T [] s21T []
	// q3 - rk

	and.w r6, r6, #0xff0
	and.w r7, r7, #0xff0

	vmov.64 r8,r9, d2
	ldr r4, [r4, #8]

	vmov.64 r10,r11, d3
	ldr r5, [r5, #8]

	// current allocation
	// r4 - s22T
	// r5 - s23T
	// r6 - s02
	// r7 - s03
	// r8 - s10
	// r9 - s11
	// r10 - s12
	// r11 - s13
	// q0 - [] s30 [] s31 [] s32 [] s33 []
	// q1 -
	// q2 - [] s00T [] s01T [] s20T [] s21T []
	// q3 - rk

	veor q2, q2, q3
	ldr r6, [r12, r6]

	vmov.64 d2, r4,r5
	ldr r7, [r12, r7]

	vmov.64 d3, r6,r7
	ldr r9, [r1, r9]

	// current allocation
	// r4 -
	// r5 -
	// r6 -
	// r7 -
	// r8 - s10
	// r9 - s11T
	// r10 - s12
	// r11 - s13
	// q0 - [] s30 [] s31 [] s32 [] s33 []
	// q1 - [] s22T [] s23T [] s02T [] s03T []
	// q2 - [] s00T [] s01T [] s20T [] s21T [] ^ rk
	// q3 -

	vmov.64 r4,r5, d0
	ldr r10, [r1, r10]

	vmov.64 r6,r7, d1
	ldr r11, [r1, r11]

	veor q2, q2, q1
	ldr r8, [r1, r8]

	// current allocation
	// r4 - s30
	// r5 - s31
	// r6 - s32
	// r7 - s33
	// r8 - s10T
	// r9 - s11T
	// r10 - s12T
	// r11 - s13T
	// q0 -
	// q1 -
	// q2 - [] s00T^s22T [] s01T^s23T [] s02T^s20T [] s03T^s21T [] ^ rk
	// q3 -

	vmov.64 d0, r9,r10
	ldr r4, [r3, r4]

	vmov.64 d1, r11,r8
	ldr r7, [r3, r7] // r7 available

	veor q0, q0, q2
	ldr r5, [r3, r5]

	// current allocation
	// r4 - s30T
	// r5 - s31T
	// r6 - s32
	// r7 - s33T
	// r8 -
	// r9 -
	// r10 -
	// r11 -
	// q0 - [] s00T^s11T^s22T [] s01T^s12T^s23T [] s02T^s13T^s20T [] s03T^s10T^s21T [] ^ rk
	// q1 -
	// q2 -
	// q3 -

	vmov.64 d2, r7,r4
	ldr r6, [r3, r6]

	vmov.64 d3, r5,r6
	adr r5, AES_shiftrows_d4T_final_gather_perm // movw+movt into rodata?

	veor q0, q0, q1
	//mov.n r10, r10 // instruction here or in front of vldrb, otherwise +1 cycle

	le lr, 1b

	// 26 cycles per round (for comparison CM7_1T is doing 27 cycles per loop and 25 for CM85_1T)

	// final round

	// sbox is at
	// bank1 - +1 +2
	// bank2 - +6 +7
	// bank3 - +8 +11
	// bank4 - +12 +13

	// only 2 alternating banks are needed, evened pressure require +1 cycle

	// not sure if 2 banked M85 instances exists, so better to target even/odd banks
	// (ra8e1 datasheet says so, but ra8d1 would be supposed to have 8 banks, with this understanding)

	// current allocation
	// r0 - rk
	// r1 -
	// r2 - out_p
	// r3 -
	// r5 - AES_shiftrows_d4T_final_gather_perm
	// r12 - AES_d4Te
	// r14 -

	// q0 - [] s00 | s10 | s20 | s30 [] s01 | s11 | s21 | s31 [] s02 | s12 | s22 | s32 [] s03 | s13 | s23 | s33 []

	// final
	// q0 - [] s00`| s11`| s22`| s33`[] s01`| s12`| s23`| s30`[] s02`| s13`| s20`| s31`[] s03`| s10`| s21`| s32`[]

	vldrb.8 q2, [r5, #0] // AES_shiftrows_d4T_final_gather_perm

	vstrb.8 q0, [sp, #0] // cant overlap into gather

	// 1 cycle free due to load to use latency of q2
	vmov.u32 q3, #0x00060000

	//mov.n r10, r10
	vorr.u32 q3, #0x00000002 // [2 6 2 6 2 6 2 6]

	vldrb.u8 q0, [sp, q2]

	//mov.n r10, r10
	vshllt.u8 q1, q0, #4

	//mov.n r10, r10
	vorr q1, q1, q3

	vshllb.u8 q0, q0, #4
	add sp, #16 // start unstacking

	vorr q0, q0, q3
	ldr r4, [sp, #32]

	// current allocation
	// q0 - [] s00 | s22 [] s01 | s23 [] s02 | s20 [] s03 | s21 [] // even rows
	// q1 - [] s11 | s33 [] s12 | s30 [] s13 | s31 [] s10 | s32 [] // odd rows
	// q2 -

	vldrb.u16 q2, [r12, q1]
	vldrb.u16 q1, [r12, q0]

	// current allocation
	// q0 -
	// q1 - [] s00`| s22`[] s01`| s23`[] s02`| s20`[] s03`| s21`[] // even rows
	// q2 - [] s11`| s33`[] s12`| s30`[] s13`| s31`[] s10`| s32`[] // odd rows

	ldrd r5,r6, [sp, #24]
	vsli.16 q1, q2, #8 // insert odd rows

	//mov.n r10, r10
	vldrw.u32 q0, [r0]

	veor q1, q1, q0 // rk

	ldrd r7,r8, [sp, #16]
	vstr.64 d2, [r2, #0] // out

	ldrd r9,r10, [sp, #8]
	vstr.64 d3, [r2, #8] //out

	ldrd r11,lr, [sp], #32+8
	bx lr

#endif
