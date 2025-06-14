/*!
 * \file CM3_1T_AES_decrypt.S
 * \brief cortex-m3/4 optimized aes decryption
 *
 * utilizes Td2 table and inv_sbox in final round
 * requires backward expanded key
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * Peter Schwabe & Ko Stoffelen @2016
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only
#if __ARM_EABI__ && __thumb2__

.syntax unified
.thumb
.text

.balign 4
// void CM3_1T_AES_decrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM3_1T_AES_decrypt
.type   CM3_1T_AES_decrypt,%function
CM3_1T_AES_decrypt:
	push {r2,r4-r11, lr} // stack out

	add.w r11, r0, #16 // final condition

	movw r14, #:lower16:AES_Td2
	movt r14, #:upper16:AES_Td2

	//rk_end = rk+16 + rounds * 16
	add r12, r11, r3, lsl #4

	//load input
	ldmia.w r1!, {r4-r7} // align loop entry

	//load initial round key
	ldmdb r12!, {r0-r3}

	//initial addroundkey
	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	// state elements will be represented with big endian order (transposed canonical state representation)
	// columns are loaded in little endian so right/left in shifts is in reverse wrt transposed canonical state representation

	// global allocation
	// r11 - rk + 16 (final)
	// r12 - current rk ptr
	// r14 - Td2

	// r0 - s00 | s10 | s20 | s30
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33

	// rotation after Td2
	// xor   16 |  8  |  0  |  24

	// r4 - s00T ^ s13T ^ s22T ^ s31T
	// r5 - s01T ^ s10T ^ s23T ^ s32T
	// r6 - s02T ^ s11T ^ s20T ^ s33T
	// r7 - s03T ^ s12T ^ s21T ^ s30T

1:	uxtb r4, r0
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

	cmp r11, r12
	bne 1b

	// final round
	movw r14, #:lower16:AES_inv_sbox
	movt r14, #:upper16:AES_inv_sbox

	// r0 - s00 | s10 | s20 | s30
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33

	//final
	// r4 - s00`| s13`| s22`| s31`
	// r5 - s01`| s10`| s23`| s32`
	// r6 - s02`| s11`| s20`| s33`
	// r7 - s03`| s12`| s21`| s30`

	uxtb r4, r0
	lsrs r6, r1, #24
	uxtb.w r9, r3, ror #8
	uxtb.w r10, r2, ror #16
	uxtb.w r8, r3, ror #16
	uxtb r5, r1
	lsrs r7, r2, #24

	ldrb.w r4, [r14, r4]
	ldrb.w r6, [r14, r6]
	ldrb.w r9, [r14, r9]
	ldrb.w r10, [r14, r10]
	ldrb.w r8, [r14, r8]
	ldrb.w r5, [r14, r5]
	ldrb.w r7, [r14, r7]

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 -  -  | s11 | s21 |  -
	// r2 - s02 | s12 |  -  |  -
	// r3 - s03 |  -  |  -  | s33
	// r4 - s00` // c0r0
	// r5 - s01` // c1r0
	// r6 - s31` // c0r3
	// r7 - s32` // c1r3
	// r8 - s23` // c1r2
	// r9 - s13` // c0r1
	// r10 - s22` // c0r2

	orr.w r4, r4, r6, lsl #24
	orr.w r4, r4, r9, lsl #8
	orr.w r4, r4, r10, lsl #16
	orr.w r5, r5, r8, lsl #16
	orr.w r5, r5, r7, lsl #24

	uxtb r6, r2
	uxtb r7, r3
	uxtb.w r8, r0, ror #16
	uxtb.w r9, r0, ror #8
	uxtb.w r10, r1, ror #16
	uxtb.w r1, r1, ror #8
	uxtb.w r2, r2, ror #8
	lsrs r3, r3, #24
	lsrs r0, r0, #24

	ldrb.w r6, [r14, r6]
	ldrb.w r7, [r14, r7]
	ldrb.w r8, [r14, r8]
	ldrb.w r9, [r14, r9]
	ldrb.w r10, [r14, r10]
	ldrb.w r1, [r14, r1]
	ldrb.w r2, [r14, r2]
	ldrb.w r3, [r14, r3]
	ldrb.w r0, [r14, r0]

	//current allocation
	// r0 - s30` // c3r3
	// r1 - s11` // c2r1
	// r2 - s12` // c3r1
	// r3 - s33` // c2r3
	// r4 - s00`| s13`| s22`| s31`
	// r5 - s01`|     | s23`| s32`
	// r6 - s02` // c2r0
	// r7 - s03` // c3r0
	// r8 - s20` // c2r2
	// r9 - s10` // c1r1
	// r10 - s21` // c3r2

	orr.w r5, r5, r9, lsl #8
	orr.w r6, r6, r8, lsl #16
	orr.w r7, r7, r10, lsl #16
	orr.w r6, r6, r1, lsl #8
	orr.w r7, r7, r2, lsl #8
	orr.w r6, r6, r3, lsl #24
	orr.w r7, r7, r0, lsl #24

	ldr r8, [sp], #4 // load output pointer and clear stack
	ldr r0, [r12, #-16]
	ldr r1, [r12, #-12]
	ldr r2, [r12, #-8]
	ldr r3, [r12, #-4]

	//current allocation
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 - s00`| s13`| s22`| s31`
	// r5 - s01`| s10`| s23`| s32`
	// r6 - s02`| s11`| s20`| s33`
	// r7 - s03`| s12`| s21`| s30`
	// r8 - out p
	// r9 -
	// r10 -

	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	stmia r8!, {r0-r3}

	pop {r4-r11, pc}

#endif
