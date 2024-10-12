/*!
 * \file CM85_d4T_AES_encrypt.S
 * \brief
 *
 * not optimized yet
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only
#if __ARM_EABI__ && __thumb2__ && (__ARM_FEATURE_MVE & 0b01)

.syntax unified
.thumb
.text

.balign 16
AES_shiftrows_d4T_gather_perm:
	.byte 0, 12, 1, 13
	.byte 10, 7, 11, 6
	.byte 5, 9, 4, 8
	.byte 15, 2, 14, 3

	// in memory layout (16 bit elements)
	// sp+0  - s00, s20, s01, s21, s02, s22, s03, s23 // even rows
	// sp+16 - s10, s30, s11, s31, s12, s32, s13, s33 // odd rows

	// required layout after gathers:
	// q0 - [] s00 [] s12 [] s20 [] s32 []
	// q1 - [] s11 [] s23 [] s31 [] s03 []
	// q2 - [] s22 [] s30 [] s02 [] s10 []
	// q3 - [] s33 [] s01 [] s13 [] s21 []

	// 2-bank friendly pattern (for cached stack) ???

AES_shiftrows_d4T_final_gather_perm:
	.byte 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11

	// in memory layout
	//  s00, s10, s20, s30, s01, s11, s21, s31, s02, s12, s22, s32, s03, s13, s23, s33

	// final layout after merge
	// q0 - [] s00`| s11`| s22`| s33`[] s01`| s12`| s23`| s30`[] s02`| s13`| s20`| s31`[] s03`| s10`| s21`| s32`[]

// void CM85_d4T_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM85_d4T_AES_encrypt
.type   CM85_d4T_AES_encrypt,%function
CM85_d4T_AES_encrypt:
	push {r4-r11,lr} //stack out
	vpush {s16-s31}

	movw r12, #:lower16:AES_d4Te
	movt r12, #:upper16:AES_d4Te

	vldrb.u8 q0, [r0], #16 // rk
	vldrb.u8 q1, [r1] // in

	veor q0, q0, q1

	subs sp, #32 // scatter area
	adr r4, AES_shiftrows_d4T_gather_perm // cant vector load by pc
	vldrb.u32 q3, [r4, #0]
	vldrb.u32 q4, [r4, #4]
	vldrb.u32 q5, [r4, #8]
	vldrb.u32 q6, [r4, #12]
	mov r4, sp // can't do widening loads by high reg

	// offsets for odd rows, even rows are done inline
	movs r5, #4
	add r5, r5, #0x000C0000

	// state and vector elements will be represented as big endian
	// (as in transposed canonical state representation)

	// global allocation
	// r0 - rk
	// r2 - out_p
	// r4 - sp (due to widening loads)
	// r5 - [ 4 12 ] (int16)
	// r12 - AES_d4Te
	// r14 - hwloop
	// q3 - [ 0 12 1 13 ] // shiftrows gather 1
	// q4 - [ 10 7 11 6 ] // shiftrows gather 2
	// q5 - [ 5 9 4 8 ]   // shiftrows gather 3
	// q6 - [ 15 2 14 3 ] // shiftrows gather 4
	// q7 -

	// row  []  0     1     2     3  []  0     1     2     3  []  0     1     2     3  []  0     1     2     3  []
	// column            0                        1                        2                        3
	// q0 - [] s00 | s10 | s20 | s30 [] s01 | s11 | s21 | s31 [] s02 | s12 | s22 | s32 [] s03 | s13 | s23 | s33 []
	//final []  s00T^s11T^s22T^s33T  []  s01T^s12T^s23T^s30T  []  s02T^s13T^s20T^s31T  []  s03T^s10T^s21T^s32T  []


	subs r3, #1 // one less
	dls lr, r3 // no skipping
.balign 8
1:
	// prepare for gathers // shifts and offsets
	vshllb.u8 q1, q0, #4
	vorr.i32 q1, #0x00080000 // [ 0 8 0 8 0 8 0 8 ]

	vshllt.u8 q0, q0, #4
	vstrh.16 q1, [r4, #0]

	vadd.i32 q0, q0, r5 // [ 4 12 4 12 4 12 4 12] // indices won't carry across 16 bit
	vstrh.16 q0, [r4, #16]

	// current allocation
	// q1 - [] s00 | s20 [] s01 | s21 [] s02 | s22 [] s03 | s23 []
	// q0 - [] s10 | s30 [] s11 | s31 [] s12 | s32 [] s13 | s33 []

	// gathers are unpipelined, can't overlap with preceeding vstr as well

	vldrh.u32 q0, [r4, q4, uxtw #1] // 3 cycles // q3 and q6 are 4 cycles here
	vldrh.u32 q1, [r4, q3, uxtw #1] // 2 cycles
	vldrh.u32 q7, [r4, q5, uxtw #1] // 2 cycles

	vldrw.u32 q2, [r12, q0] // 2 cycles
	vldrw.u32 q0, [r12, q1] // 2 cycles
	vldrw.u32 q1, [r12, q7] // 2 cycles

	veor q0, q0, q2

	vldrh.u32 q2, [r4, q6, uxtw #1] // 2 cycles

	veor q0, q0, q1

	// apply rk
	vldrw.u32 q1, [r0], #16
	veor q0, q0, q1

	vldrw.u32 q1, [r12, q2] // 2 cycles
	veor q0, q0, q1

	le lr, 1b

	// 28 cycles


	// final round

	// sbox at
	// bank1 - +1 +2
	// bank2 - +6 +7
	// bank3 - +8 +11
	// bank4 - +12 +13

	// r5 - [ 4 12 ] (int16) // bank 2 and 4


	// scalar can be inserted into loop or prologue
	adds r6, r5, #2 // recycle r5, target actual sbox in bank2
	subs r7, r6, #0x00040004


	adr r8, AES_shiftrows_d4T_final_gather_perm
	vldrb.8 q2, [r8]



	// only 2 alternating banks are needed, but do 4
	// r6 - [ 6 12 ] (int16) // bank 2 and 4
	// r7 - [ 2 8 ] (int16) // bank 1 and 3

	// current allocation
	// q0 - [] s00 | s10 | s20 | s30 [] s01 | s11 | s21 | s31 [] s02 | s12 | s22 | s32 [] s03 | s13 | s23 | s33 []
	// q1 -
	// q2 - [ 0 5 10 15 4 9 14 3 8 13 2 7 12 1 6 11 ] // shiftrows gather
	// q7 -

	// final
	// q0 - [] s00`| s11`| s22`| s33`[] s01`| s12`| s23`| s30`[] s02`| s13`| s20`| s31`[] s03`| s10`| s21`| s32`[]


	vstrb.8 q0, [r4, #0]

	// cant overlap into gather

	vldrb.u8 q0, [r4, q2]

	// prepare for sboxing
	vshllt.u8 q1, q0, #4
	vshllb.u8 q0, q0, #4

	vadd.i32 q0, q0, r6
	vadd.i32 q1, q1, r7

	// current allocation
	// q0 - [] s00 | s22 [] s01 | s23 [] s02 | s20 [] s03 | s21 [] // even rows
	// q1 - [] s11 | s33 [] s12 | s30 [] s13 | s31 [] s10 | s32 [] // odd rows
	// q7 -

	vldrb.u16 q7, [r12, q0]
	vldrb.u16 q0, [r12, q1]

	// current allocation
	// q0 - [] s11`| s33`[] s12`| s30`[] s13`| s31`[] s10`| s32`[] // odd rows
	// q1 -
	// q7 - [] s00`| s22`[] s01`| s23`[] s02`| s20`[] s03`| s21`[] // even rows

	vsli.16 q7, q0, #8 // insert odd rows

	// apply rk
	vldrw.u32 q1, [r0]
	veor q7, q7, q1


	vstrb.8 q7, [r2]




	add sp, #32 // scatter area

	vpop {s16-s31}
	pop {r4-r11,pc}

#endif
