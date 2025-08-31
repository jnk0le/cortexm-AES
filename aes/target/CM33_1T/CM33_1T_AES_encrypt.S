/*!
 * \file CM33_1T_AES_encrypt.S
 * \brief cortex-m33 optimized aes encryption
 *
 * utilizes Te2 table
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
// void CM33_1T_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM33_1T_AES_encrypt
.type   CM33_1T_AES_encrypt,%function
CM33_1T_AES_encrypt:
	push {r2,r4-r7,r11,lr} // stack out
	add r11, r0, r3, lsl #4 // rk_end-16 = rk + rounds * 16

	movw r14, #:lower16:AES_Te2
	movt r14, #:upper16:AES_Te2

	mov r12, r0

	//load input
	ldmia r1!, {r4-r7}
	//load key
	ldmia r12!, {r0-r3}

	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	// one uxtb skewed to allow branch dual issue
	uxtb.w r4, r0

	// state elements will be represented with big endian order (transposed canonical state representation)
	// columns are loaded in little endian so right/left in shifts is in reverse wrt transposed canonical state representation

	// global allocation
	// r11 - final ptr
	// r12 - current rk ptr
	// r14 - Te2

	// r0 - s00 | s10 | s20 | s30
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33

	// rotation after Te2
	// xor   16 |  8  |  0  |  24

	// r4 - s00T ^ s11T ^ s22T ^ s33T
	// r5 - s01T ^ s12T ^ s23T ^ s30T
	// r6 - s02T ^ s13T ^ s20T ^ s31T
	// r7 - s03T ^ s10T ^ s21T ^ s32T

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
	lsrs r6, r3, #24
	ldr.w r4, [r14, r4, lsl #2]
	ldr.w r6, [r14, r6, lsl #2]

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 -  -  | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 |  -
	// r4 - s00T // c0 ror16
	// r5 - s01 // c1 ror16
	// r6 - s33T // c0 ror24
	// r7 -

	uxtb.w r7, r2, ror #16
	ldr.w r7, [r14, r7, lsl #2]

	eor.w r4, r4, r6, ror #8 // effective ror #24
	ldr.w r5, [r14, r5, lsl #2]

	uxtb.w r6, r1, ror #8
	eor.w r4, r7, r4, ror #16

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 | s23 |  -
	// r4 - s00T ^ s22T ^ s33T // c0
	// r5 - s01T // c1 ror16
	// r6 - s11 // c0 ror8
	// r7 -

	ldr.w r6, [r14, r6, lsl #2]
	uxtb r7, r3, ror #16
	ldr.w r7, [r14, r7, lsl #2]
	eor.w r4, r4, r6, ror #8
	lsrs r6, r0, #24

	//current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r5 - s01T // c1 ror16
	// r6 - s30 // c1 ror24
	// r7 - s23T // c1 ror0

	ldr.w r6, [r14, r6, lsl #2]
	eor.w r5, r7, r5, ror #16

	uxtb.w r7, r2, ror #8
	ldr.w r7, [r14, r7, lsl #2]
	eor.w r5, r5, r6, ror #24

	//current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r5 - s01T ^ s23T ^ s30T // c1
	// r6 -
	// r7 - s12T // c1 ror8

	uxtb r6, r2
	ldr.w r6, [r14, r6, lsl #2]

	eor.w r5, r5, r7, ror #8

	uxtb.w r7, r0, ror #16
	ldr.w r7, [r14, r7, lsl #2]

	//current allocation
	// r0 -  -  | s10 |  -  |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 -  -  |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r5 - s01T ^ s12T ^ s23T ^ s30T // c1
	// r6 - s02T // c2 ror16
	// r7 - s20T // c2 ror0

	lsrs r2, r2, #24
	ldr.w r2, [r14, r2, lsl #2]

	eor.w r6, r7, r6, ror #16

	uxtb.w r7, r3, ror #8
	ldr.w r7, [r14, r7, lsl #2]

	//current allocation
	// r0 -  -  | s10 |  -  |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s32T // c3 ror24
	// r3 - s03 |  -  |  -  |  -
	// r4 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r5 - s01T ^ s12T ^ s23T ^ s30T // c1
	// r6 - s02T ^ s20T // c2
	// r7 - s13T // c2 ror8

	uxtb r3, r3
	eor.w r6, r6, r7, ror #8
	lsrs r7, r1, #24

	uxtb r1, r1, ror #16
	ldr.w r1, [r14, r1, lsl #2]

	//current allocation
	// r0 -  -  | s10 |  -  |  -
	// r1 - s21T // c3 ror0
	// r2 - s32T // c3 ror24
	// r3 - s03 // c3 ror16
	// r4 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r5 - s01T ^ s12T ^ s23T ^ s30T // c1
	// r6 - s02T ^ s13T ^ s20T // c2
	// r7 - s31 // c2 ror24

	uxtb.w r0, r0, ror #8
	ldr.w r3, [r14, r3, lsl #2]
	eor.w r1, r1, r2, ror #24
	ldr.w r7, [r14, r7, lsl #2]
	eor.w r1, r1, r3, ror #16

	//current allocation
	// r0 - s10 // c3 ror8
	// r1 - s03T ^ s21T ^ s32T // c3
	// r2 -
	// r3 -
	// r4 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r5 - s01T ^ s12T ^ s23T ^ s30T // c1
	// r6 - s02T ^ s13T ^ s20T // c2
	// r7 - s31T // c2 ror24

	ldr.w r0, [r14, r0, lsl #2]
	eor.w r6, r6, r7, ror #24
	eor.w r7, r1, r0, ror #8

	//current allocation
	// r0 -
	// r1 -
	// r2 -
	// r3 -
	// r4 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r5 - s01T ^ s12T ^ s23T ^ s30T // c1
	// r6 - s02T ^ s13T ^ s20T ^ s31T // c2
	// r7 - s03T ^ s10T ^ s21T ^ s32T // c3

	ldmia r12!, {r0-r3} // load rk

	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	cmp r12, r11
	uxtb r4, r0 // skewed
	bne 1b

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33
	// r4 - s00 // c0 ???
	// r5 -
	// r6 -
	// r7 -

	//final
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02`| s13`| s20`| s31`
	// r7 - s03`| s10`| s21`| s32`

	uxtb r5, r1
	lsrs r6, r3, #24
	ldrb.w r4, [r14, r4, lsl #2]
	ldrb.w r6, [r14, r6, lsl #2]

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33
	// r4 - s00` // c0r0
	// r5 - s01 // c1r0
	// r6 - s33` // c0r3
	// r7 -

	uxtb.w r7, r2, ror #16
	ldrb.w r7, [r14, r7, lsl #2]

	orr.w r4, r4, r6, lsl #24
	ldrb.w r5, [r14, r5, lsl #2]

	uxtb.w r6, r1, ror #8
	orr.w r4, r4, r7, lsl #16

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 | s23 |  -
	// r4 - s00`|     | s22`| s33`
	// r5 - s01` // c1r0
	// r6 - s11 // c0r1
	// r7 -

	ldrb.w r6, [r14, r6, lsl #2]
	uxtb r7, r3, ror #16
	ldrb.w r7, [r14, r7, lsl #2]
	orr.w r4, r4, r6, lsl #8
	lsrs r6, r0, #24

	//current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01` // c1r0
	// r6 - s30 // c1r3
	// r7 - s23` // c1r2

	ldrb.w r6, [r14, r6, lsl #2]
	orr.w r5, r5, r7, lsl #16

	uxtb.w r7, r2, ror #8
	ldrb.w r7, [r14, r7, lsl #2]
	orr.w r5, r5, r6, lsl #24

	//current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`|     | s23`| s30`
	// r6 -
	// r7 - s12` // c1r1

	uxtb r6, r2
	ldrb.w r6, [r14, r6, lsl #2]

	orr.w r5, r5, r7, lsl #8

	uxtb.w r7, r0, ror #16
	ldrb.w r7, [r14, r7, lsl #2]

	//current allocation
	// r0 -  -  | s10 |  -  |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 -  -  |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02` // c2r0
	// r7 - s20` // c2r2

	lsrs r2, r2, #24
	ldrb.w r2, [r14, r2, lsl #2]

	orr.w r6, r6, r7, lsl #16

	uxtb.w r7, r3, ror #8
	ldrb.w r7, [r14, r7, lsl #2]

	//current allocation
	// r0 -  -  | s10 |  -  |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s32` // c3r3
	// r3 - s03 |  -  |  -  |  -
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02`|  -  | s20`|  -
	// r7 - s13` // c2r1

	uxtb r3, r3
	orr.w r6, r6, r7, lsl #8
	lsrs r7, r1, #24

	uxtb r1, r1, ror #16
	ldrb.w r1, [r14, r1, lsl #2]

	//current allocation
	// r0 -  -  | s10 |  -  |  -
	// r1 - s21` // c3r2
	// r2 - s32` // c3r3
	// r3 - s03 // c3r0
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02`| s13`| s20`|  -
	// r7 - s31 // c2r3

	uxtb.w r0, r0, ror #8
	ldrb.w r3, [r14, r3, lsl #2]
	orr.w r1, r1, r2, lsl #8 // need to shift #16 more
	ldrb.w r7, [r14, r7, lsl #2]
	orr.w r1, r3, r1, lsl #16

	//current allocation
	// r0 - s10 // c3r1
	// r1 - s03`|  -  | s21`| s32`
	// r2 -
	// r3 -
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02`| s13`| s20`|  -
	// r7 - s31` // c2r3

	ldrb.w r0, [r14, r0, lsl #2]
	orr.w r6, r6, r7, lsl #24
	orr.w r7, r1, r0, lsl #8

	//current allocation
	// r0 -
	// r1 -
	// r2 -
	// r3 -
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02`| s13`| s20`| s31`
	// r7 - s03`| s10`| s21`| s32`

	ldmia r12!, {r0-r3} // load rk

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
