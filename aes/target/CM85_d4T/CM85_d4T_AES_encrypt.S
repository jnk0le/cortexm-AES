/*!
 * \file CM85_d4T_AES_encrypt.S
 * \brief
 *
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

	// 4 banks
	//bank1 - 0 1 2 3
	//bank2 - 4 5 6 7
	//bank3 - 8 9 10 11
	//bank4 - 12 13 14 15

	// 2 banks (each pair still accesses different bank)
	//bank1 - 0 1 2 3   8 9 10 11
	//bank2 - 4 5 6 7   12 13 14 15

// void CM85_d4T_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM85_d4T_AES_encrypt
.type   CM85_d4T_AES_encrypt,%function
CM85_d4T_AES_encrypt:
	subs r3, #1 // one less
	strd r4,lr, [sp, #-72]! // possible to not stack those, but constants would get 48 byte larger (no gain in prologue/epilogue)

	adr r4, AES_shiftrows_d4T_gather_perm // cant vector load by pc
	vldrb.u8 q1, [r1] // in

	vstrw.32 q4, [sp, #8] // this one can't predecrement

	vldrb.u8 q0, [r0], #16 // rk

	veor q0, q0, q1

	subs sp, #32 // scatter area // shuffling area needs to be at sp+0
	dls lr, r3 // no skipping

	//mov.n r10, r10
	vldrb.u32 q4, [r4, #0]
	vstrw.32 q5, [sp, #32+8+16]
	vldrb.u32 q5, [r4, #4]
	vstrw.32 q6, [sp, #32+8+32]
	vldrb.u32 q6, [r4, #8]
	vstrw.32 q7, [sp, #32+8+48]
	vldrb.u32 q7, [r4, #12]

	// state and vector elements will be represented with big endian representation
	// (as in transposed canonical state representation)

	// global allocation
	// r0 - rk
	// r1 -
	// r2 - out_p
	// r3 - [ 4 12 ] (int16)
	// r4 - pointer to shiftrows constants
	// r12 - AES_d4Te
	// r14 - hwloop
	// q4 - [ 0 12 1 13 ] // shiftrows gather 1
	// q5 - [ 10 7 11 6 ] // shiftrows gather 2
	// q6 - [ 5 9 4 8 ]   // shiftrows gather 3
	// q7 - [ 15 2 14 3 ] // shiftrows gather 4

	// row  []  0     1     2     3  []  0     1     2     3  []  0     1     2     3  []  0     1     2     3  []
	// column            0                        1                        2                        3
	// q0 - [] s00 | s10 | s20 | s30 [] s01 | s11 | s21 | s31 [] s02 | s12 | s22 | s32 [] s03 | s13 | s23 | s33 []
	//final []  s00T^s11T^s22T^s33T  []  s01T^s12T^s23T^s30T  []  s02T^s13T^s20T^s31T  []  s03T^s10T^s21T^s32T  []

.balign 8
1:
	// prepare for gathers // shifts and offsets
	//mov.n r10, r10 // can't use due to vldrb from prologue
	vshllb.u8 q1, q0, #4

	movs r3, #4 // offsets for odd rows, even rows are done inline
	vorr.i32 q1, #0x00080000 // [ 0 8 0 8 0 8 0 8 ]

	add r3, r3, #0x000C0000 // finish offset for odd rows
	vshllt.u8 q0, q0, #4

	movw r12, #:lower16:AES_d4Te
	vstrh.16 q1, [sp, #0]

	vadd.i32 q0, q0, r3 // [ 4 12 4 12 4 12 4 12] // indices won't carry across 16 bit
	movt r12, #:upper16:AES_d4Te
	vstrh.16 q0, [sp, #16]

	// current allocation
	// q1 - [] s00 | s20 [] s01 | s21 [] s02 | s22 [] s03 | s23 []
	// q0 - [] s10 | s30 [] s11 | s31 [] s12 | s32 [] s13 | s33 []

	// gathers are unpipelined, can't overlap with preceeding vstr as well

	vldrh.u32 q0, [sp, q5, uxtw #1] // 3 cycles // q4 and q7 are 4 cycles here
	vldrh.u32 q1, [sp, q4, uxtw #1] // 2 cycles
	vldrh.u32 q3, [sp, q6, uxtw #1] // 2 cycles

	vldrw.u32 q2, [r12, q0] // 2 cycles
	vldrw.u32 q0, [r12, q1] // 2 cycles
	vldrw.u32 q1, [r12, q3] // 2 cycles

	//mov.n r10, r10
	veor q0, q0, q2

	vldrh.u32 q2, [sp, q7, uxtw #1] // 2 cycles

	//mov.n r10, r10
	veor q0, q0, q1

	// apply rk
	//mov.n r10, r10
	vldrw.u32 q1, [r0], #16
	veor q0, q0, q1

	vldrw.u32 q1, [r12, q2] // 2 cycles

	//mov.n r10, r10
	veor q0, q0, q1

	le lr, 1b

	// 28 cycles per loop (for comparison CM7_1T is doing 27 cycles per loop and 25 for CM85_1T)

	// final round

	// sbox is at
	// bank1 - +1 +2
	// bank2 - +6 +7
	// bank3 - +8 +11
	// bank4 - +12 +13

	// only 2 alternating banks are needed
	// [ 6 12 ] (int16) // bank 2 and 4
	// [ 2 8 ] (int16) // bank 1 and 3 (differs by 0x00040004)

	// current allocation
	// r0 - rk
	// r1 -
	// r2 - out_p
	// r3 - [ 4 12 ] (int16) // bank 2 and 4
	// r4 - pointer to shiftrows constants
	// r12 - AES_d4Te
	// r14 -
	// q0 -
	// q1 -
	// q2 -
	// q3 -
	// q4:q7 - loop shiftrows, preserved in CTR mode

	// scalar can be inserted into loop or prologue
	adds r3, r3, #2 // recycle r3, target actual sbox in bank2
	vldrb.8 q2, [r4, #16] // reach into AES_shiftrows_d4T_final_gather_perm

	// 1 vector instruction is free here
	vdup.i32 q3, r3

	// current allocation
	// r0 - rk
	// r1 -
	// r2 - out_p
	// r3 - [ 4 12 ] (int16) // bank 2 and 4
	// q0 - [] s00 | s10 | s20 | s30 [] s01 | s11 | s21 | s31 [] s02 | s12 | s22 | s32 [] s03 | s13 | s23 | s33 []
	// q1 -
	// q2 - [ 0 5 10 15 4 9 14 3 8 13 2 7 12 1 6 11 ] // shiftrows gather
	// q3 - [ 6 12 6 12 6 12 6 12] (int16) // bank 2 and 4

	// final
	// q0 - [] s00`| s11`| s22`| s33`[] s01`| s12`| s23`| s30`[] s02`| s13`| s20`| s31`[] s03`| s10`| s21`| s32`[]

	subs r1, r3, #0x00040004
	vstrb.8 q0, [sp, #0] // cant overlap into gather

	// another vdup ?????

	vldrb.u8 q0, [sp, q2]

	// prepare for sboxing
	ldrd r4,lr, [sp, #32] // start unstacking
	vshllt.u8 q1, q0, #4

	vldrw.32 q4, [sp, #32+8+0]
	vorr q1, q1, q3

	vldrw.32 q5, [sp, #32+8+16]

	vshllb.u8 q0, q0, #4
	vldrw.32 q6, [sp, #32+8+32]
	vadd.i32 q0, q0, r1 // even out DTCM bank accesses // needs vorr if can't overlap with epilogue

	// current allocation
	// q0 - [] s00 | s22 [] s01 | s23 [] s02 | s20 [] s03 | s21 [] // even rows
	// q1 - [] s11 | s33 [] s12 | s30 [] s13 | s31 [] s10 | s32 [] // odd rows
	// q2 -
	// q7 -

	vldrb.u16 q2, [r12, q1]
	vldrb.u16 q1, [r12, q0]

	// current allocation
	// q0 -
	// q1 - [] s00`| s22`[] s01`| s23`[] s02`| s20`[] s03`| s21`[] // even rows
	// q2 - [] s11`| s33`[] s12`| s30`[] s13`| s31`[] s10`| s32`[] // odd rows
	// q7 -

	vldrw.32 q7, [sp, #32+8+48]

	vsli.16 q1, q2, #8 // insert odd rows

	// apply rk
	vldrw.u32 q0, [r0]
	veor q1, q1, q0

	vstrb.8 q1, [r2]

	add sp, #32+8+64
	bx lr

#endif
