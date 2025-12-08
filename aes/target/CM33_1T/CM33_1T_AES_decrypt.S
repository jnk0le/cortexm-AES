/*!
 * \file CM33_1T_AES_decrypt.S
 * \brief cortex-m33 optimized aes decryption
 *
 * utilizes Td2 table and inv_sbox in final round
 * requires backward expanded key
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only
#if __ARM_EABI__ && __thumb2__

.syntax unified
.thumb
.text

.balign 4
// void CM33_1T_AES_decrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM33_1T_AES_decrypt
.type   CM33_1T_AES_decrypt,%function
CM33_1T_AES_decrypt:
	push {r2,r4-r7,r11,lr} // stack out

	add.w r11, r0, #16 // final condition

	movw r14, #:lower16:AES_Td2
	movt r14, #:upper16:AES_Td2

	//rk_end = rk+16 + rounds * 16
	add r12, r11, r3, lsl #4

	ldmia r1!, {r4-r7} // load input
	ldmdb r12!, {r0-r3} // load key

	// initial addroundkey
	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	// one uxtb skewed to allow branch dual issue
	uxtb r4, r0

	// state elements will be represented with big endian order (transposed canonical state representation)
	// columns are loaded in little endian so right/left in shifts is in reverse wrt transposed canonical state representation

	// global allocation
	// r11 - final ptr
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

1:
	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33
	// r4 - s00 // c0 ror16
	// r5 -
	// r6 -
	// r7 -

	uxtb r5, r1
	lsrs r6, r1, #24
	ldr.w r4, [r14, r4, lsl #2]
	ldr.w r6, [r14, r6, lsl #2]

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 -  -  | s11 | s21 |  -
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33
	// r4 - s00T // c0 ror16
	// r5 - s01 // c1 ror16
	// r6 - s31T // c0 ror24
	// r7 -

	uxtb.w r7, r2, ror #16
	ldr.w r7, [r14, r7, lsl #2]

	eor.w r4, r4, r6, ror #8 // effective ror #24
	ldr.w r5, [r14, r5, lsl #2]

	uxtb.w r6, r3, ror #8
	eor.w r4, r7, r4, ror #16

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 -  -  | s11 | s21 |  -
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 |  -  | s23 | s33
	// r4 - s00T ^ s22T ^ s31T // c0
	// r5 - s01T // c1 ror16
	// r6 - s13 // c0 ror8
	// r7 -

	ldr.w r6, [r14, r6, lsl #2]
	uxtb r7, r3, ror #16
	ldr.w r7, [r14, r7, lsl #2]
	eor.w r4, r4, r6, ror #8
	lsrs r6, r2, #24

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 -  -  | s11 | s21 |  -
	// r2 - s02 | s12 |  -  |  -
	// r3 - s03 |  -  |  -  | s33
	// r4 - s00T ^ s13T ^ s22T ^ s31T // c0
	// r5 - s01T // c1 ror16
	// r6 - s32 // c1 ror24
	// r7 - s23T // c1 ror0

	ldr.w r6, [r14, r6, lsl #2]
	eor.w r5, r7, r5, ror #16

	uxtb.w r7, r0, ror #8
	ldr.w r7, [r14, r7, lsl #2]
	eor.w r5, r5, r6, ror #24

	//current allocation
	// r0 -  -  |  -  | s20 | s30
	// r1 -  -  | s11 | s21 |  -
	// r2 - s02 | s12 |  -  |  -
	// r3 - s03 |  -  |  -  | s33
	// r4 - s00T ^ s13T ^ s22T ^ s31T // c0
	// r5 - s01T ^ s23T ^ s32T // c1
	// r6 -
	// r7 - s10T // c1 ror8

	uxtb r6, r2
	ldr.w r6, [r14, r6, lsl #2]

	eor.w r5, r5, r7, ror #8

	uxtb.w r7, r0, ror #16
	ldr.w r7, [r14, r7, lsl #2]

	//current allocation
	// r0 -  -  |  -  |  -  | s30
	// r1 -  -  | s11 | s21 |  -
	// r2 -  -  | s12 |  -  |  -
	// r3 - s03 |  -  |  -  | s33
	// r4 - s00T ^ s13T ^ s22T ^ s31T // c0
	// r5 - s01T ^ s10T ^ s23T ^ s32T // c1
	// r6 - s02T // c2 ror16
	// r7 - s20T // c2 ror0

	lsrs r0, r0, #24
	ldr.w r0, [r14, r0, lsl #2]

	eor.w r6, r7, r6, ror #16

	uxtb.w r7, r1, ror #8
	ldr.w r7, [r14, r7, lsl #2]

	//current allocation
	// r0 - s30T // c3 ror24
	// r1 -  -  |  -  | s21 |  -
	// r2 -  -  | s12 |  -  |  -
	// r3 - s03 |  -  |  -  | s33
	// r4 - s00T ^ s13T ^ s22T ^ s31T // c0
	// r5 - s01T ^ s10T ^ s23T ^ s32T // c1
	// r6 - s02T ^ s20T // c2
	// r7 - s11T // c2 ror8

	uxtb r1, r1, ror #16
	ldr.w r1, [r14, r1, lsl #2]

	eor.w r6, r6, r7, ror #8
	lsrs r7, r3, #24
	uxtb r3, r3

	//current allocation
	// r0 - s30T // c3 ror24
	// r1 - s21T // c3 ror0
	// r2 -  -  | s12 |  -  |  -
	// r3 - s03 // c3 ror16
	// r4 - s00T ^ s13T ^ s22T ^ s31T // c0
	// r5 - s01T ^ s10T ^ s23T ^ s32T // c1
	// r6 - s02T ^ s11T ^ s20T // c2
	// r7 - s33 // c2 ror24

	uxtb.w r2, r2, ror #8
	ldr.w r3, [r14, r3, lsl #2]
	eor.w r1, r1, r0, ror #24
	ldr.w r7, [r14, r7, lsl #2]
	eor.w r1, r1, r3, ror #16

	//current allocation
	// r0 -
	// r1 - s03T ^ s21T ^ s30T // c3
	// r2 - s12 // c3 ror8
	// r3 -
	// r4 - s00T ^ s13T ^ s22T ^ s31T // c0
	// r5 - s01T ^ s10T ^ s23T ^ s32T // c1
	// r6 - s02T ^ s11T ^ s20T // c2
	// r7 - s33T // c2 ror24

	ldr.w r2, [r14, r2, lsl #2]
	eor.w r6, r6, r7, ror #24
	eor.w r7, r1, r2, ror #8

	//current allocation
	// r0 -
	// r1 -
	// r2 -
	// r3 -
	// r4 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r5 - s01T ^ s12T ^ s23T ^ s30T // c1
	// r6 - s02T ^ s13T ^ s20T ^ s31T // c2
	// r7 - s03T ^ s10T ^ s21T ^ s32T // c3

	ldmdb r12!, {r0-r3} // laod rk

	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	cmp r11, r12

	uxtb r4, r0 // skewed
	bne 1b

	// final round
	movw r14, #:lower16:AES_inv_sbox
	movt r14, #:upper16:AES_inv_sbox

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33
	// r4 - s00 // c0r0
	// r5 -
	// r6 -
	// r7 -

	//final
	// r4 - s00`| s13`| s22`| s31`
	// r5 - s01`| s10`| s23`| s32`
	// r6 - s02`| s11`| s20`| s33`
	// r7 - s03`| s12`| s21`| s30`

	uxtb r5, r1
	lsrs r6, r1, #24
	ldrb.w r4, [r14, r4]
	ldrb.w r6, [r14, r6]

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 -  -  | s11 | s21 |  -
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33
	// r4 - s00` // c0r0
	// r5 - s01 // c1r0
	// r6 - s31` // c0r3
	// r7 -

	uxtb.w r7, r2, ror #16
	ldrb.w r7, [r14, r7]

	orr.w r4, r4, r6, lsl #24
	ldrb.w r5, [r14, r5]

	uxtb.w r6, r3, ror #8
	orr.w r4, r4, r7, lsl #16

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 -  -  | s11 | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 |  -  | s23 | s33
	// r4 - s00`|     | s22`| s31`
	// r5 - s01` // c1r0
	// r6 - s13 // c0r1
	// r7 -

	ldrb.w r6, [r14, r6]
	uxtb r7, r3, ror #16
	ldrb.w r7, [r14, r7]
	orr.w r4, r4, r6, lsl #8
	lsrs r6, r2, #24

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 -  -  | s11 | s21 |  -
	// r2 - s02 | s12 |  -  |  -
	// r3 - s03 |  -  |  -  | s33
	// r4 - s00`| s13`| s22`| s31`
	// r5 - s01` // c1r0
	// r6 - s32 // c1r3
	// r7 - s23` // c1r2

	ldrb.w r6, [r14, r6]
	orr.w r5, r5, r7, lsl #16

	uxtb.w r7, r0, ror #8
	ldrb.w r7, [r14, r7]
	orr.w r5, r5, r6, lsl #24

	//current allocation
	// r0 -  -  |  -  | s20 | s30
	// r1 -  -  | s11 | s21 |  -
	// r2 - s02 | s12 |  -  |  -
	// r3 - s03 |  -  |  -  | s33
	// r4 - s00`| s13`| s22`| s31`
	// r5 - s01`|     | s23`| s32`
	// r6 -
	// r7 - s10` // c1r1

	uxtb r6, r2
	ldrb.w r6, [r14, r6]

	orr.w r5, r5, r7, lsl #8

	uxtb.w r7, r0, ror #16
	ldrb.w r7, [r14, r7]

	//current allocation
	// r0 -  -  |  -  |  -  | s30
	// r1 -  -  | s11 | s21 |  -
	// r2 -  -  | s12 |  -  |  -
	// r3 - s03 |  -  |  -  | s33
	// r4 - s00`| s13`| s22`| s31`
	// r5 - s01`| s10`| s23`| s32`
	// r6 - s02` // c2r0
	// r7 - s20` // c2r2

	lsrs r0, r0, #24
	ldrb.w r0, [r14, r0]

	orr.w r6, r6, r7, lsl #16

	uxtb.w r7, r1, ror #8
	ldrb.w r7, [r14, r7]

	//current allocation
	// r0 - s30` // c3r3
	// r1 -  -  |  -  | s21 |  -
	// r2 -  -  | s12 |  -  |  -
	// r3 - s03 |  -  |  -  | s33
	// r4 - s00`| s13`| s22`| s31`
	// r5 - s01`| s10`| s23`| s32`
	// r6 - s02`|     | s20`|
	// r7 - s11` // c2r1

	uxtb r1, r1, ror #16
	ldrb.w r1, [r14, r1]

	orr.w r6, r6, r7, lsl #8
	lsrs r7, r3, #24
	uxtb r3, r3

	//current allocation
	// r0 - s30` // c3r3
	// r1 - s21` // c3r2
	// r2 -  -  | s12 |  -  |  -
	// r3 - s03 // c3r0
	// r4 - s00`| s13`| s22`| s31`
	// r5 - s01`| s10`| s23`| s32`
	// r6 - s02`| s11`| s20`|
	// r7 - s33 // c2r3

	uxtb r2, r2, ror #8
	ldrb.w r3, [r14, r3]
	orr.w r1, r1, r0, lsl #8 // need to shift #16 more
	ldrb.w r7, [r14, r7]
	orr.w r1, r3, r1, lsl #16

	//current allocation
	// r0 -
	// r1 - s03`|     | s21`| s30`
	// r2 - s12 // c3r1
	// r3 -
	// r4 - s00`| s13`| s22`| s31`
	// r5 - s01`| s10`| s23`| s32`
	// r6 - s02`| s11`| s20`|
	// r7 - s33` // c2r3

	ldrb.w r2, [r14, r2]
	orr.w r6, r6, r7, lsl #24
	orr.w r7, r1, r2, lsl #8

	ldmdb r12!, {r0-r3} // load rk

	eors r4, r0 // need caller saved loreg for pointer
	eors r1, r5
	ldr r0, [sp], #4 // load out ptr
	eors r2, r6
	eors r3, r7

	str r4, [r0, #0]

	pop {r4-r7,r11,lr}

	// store rest of the output
	str r1, [r0, #4]
	str r2, [r0, #8]
	str r3, [r0, #12]

	bx lr

#endif
