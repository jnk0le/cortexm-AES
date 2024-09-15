/*!
 * \file CM85_1T_AES_encrypt.S
 * \brief
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only (__ARM_ARCH_8_1M_MAIN__ doesn't work)
#if __ARM_EABI__ && __thumb2__ && (__ARM_FEATURE_MVE & 0b01)

.syntax unified
.thumb
.text

.balign 8
// void CM85_1T_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM85_1T_AES_encrypt
.type   CM85_1T_AES_encrypt,%function
CM85_1T_AES_encrypt:
	strd r2,r4, [sp, #-40]! // stack out
	subs r3, #1 // one less

	strd r5,r6, [sp, #8]
	ldrd r4,r5, [r1, #0] // load input

	strd r7,r8, [sp, #16]
	ldrd r6,r7, [r1, #8] // load input

	strd r9,r10, [sp, #24]
	mov r12, r0

	strd r11,lr, [sp, #32]
	dls lr, r3 // init HW loop

	ldrd r0,r1, [r12], #8 // load key
	movw r11, #:lower16:AES_Te2

	ldrd r2,r3, [r12], #8 // load key
	movt r11, #:upper16:AES_Te2

	//initial addroundkey
	eors r0, r4
	eors r1, r5

	eors r2, r6
	eors r3, r7

	// global allocation
	// r11 - Te2
	// r12 - current rk ptr
	// r14 - hwloop

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

//loop is 8+4 aligned but 2 first insns are .n
1:
	// r0 must be available in EX2, r3 in EX3 here
	uxtb r4, r0
	lsrs r5, r0, #24

	ubfx r8, r3, #16, #8
	ldr r5, [r11, r5, lsl #2] // can't use r4 (slippery condition)

	// current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 |  -  | s33
	// r4 - s00 // c0 ror16
	// r5 - s30T // c1 ror24
	// r6 -
	// r7 -
	// r8 - s23 // c1 ror0
	// r9 -
	// r10 -

	uxtb r6, r1
	ldr r4, [r11, r4, lsl #2]

	ubfx r9, r2, #16, #8
	ldr r8, [r11, r8, lsl #2]

	// current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  | s11 | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 |  -  | s33
	// r4 - s00T // c0 ror16
	// r5 - s30T // c1 ror24
	// r6 - s01 // c1 ror16
	// r7 -
	// r8 - s23T // c1 ror0
	// r9 - s22 // c0 ror0
	// r10 -

	lsrs r7, r3, #24
	ldr r6, [r11, r6, lsl #2]

	ubfx r10, r0, #16, #8
	ldr r9, [r11, r9, lsl #2]

	// current allocation
	// r0 -  -  | s10 |  -  |  -
	// r1 -  -  | s11 | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00T // c0 ror16
	// r5 - s30T // c1 ror24
	// r6 - s01T // c1 ror16
	// r7 - s33 // c0 ror24
	// r8 - s23T // c1 ror0
	// r9 - s22T // c0 ror0
	// r10 - s20 // c2 ror0

	eor.w r8, r8, r6, ror #16
	ldr r7, [r11, r7, lsl #2]

	ubfx r6, r1, #8, #8
	eor.w r9, r9, r4, ror #16

	// current allocation
	// r0 -  -  | s10 |  -  |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 -
	// r5 - s30T // c1 ror24
	// r6 - s11 // c0 ror8
	// r7 - s33T // c0 ror24
	// r8 - s01T ^ s23T // c1
	// r9 - s00T ^ s22T // c0
	// r10 - s20 // c2 ror0

	lsrs r4, r1, #24
	ldr r6, [r11, r6, lsl #2]

	eor.w r7, r9, r7, ror #24
	ldr r4, [r11, r4, lsl #2]

	// current allocation
	// r0 -  -  | s10 |  -  |  -
	// r1 -  -  |  -  | s21 |  -
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s31T // c2 ror24
	// r5 - s30T // c1 ror24
	// r6 - s11T // c0 ror8
	// r7 - s00T ^ s22T ^ s33T // c0
	// r8 - s01T ^ s23T // c1
	// r9 -
	// r10 - s20 // c2 ror0

	ubfx r9, r0, #8, #8
	ldr r10, [r11, r10, lsl #2]

	eor.w r5, r8, r5, ror #24
	eor.w r7, r7, r6, ror #8

	// current allocation
	// r0 -
	// r1 -  -  |  -  | s21 |  -
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s31T // c2 ror24
	// r5 - s01T ^ s23T ^ s30T // c1
	// r6 -
	// r7 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r8 -
	// r9 - s10 // c3 ror8
	// r10 - s20T // c2 ror0

	ubfx r8, r1, #16, #8
	ldr r9, [r11, r9, lsl #2]

	ubfx r6, r2, #8, #8
	ldr r8, [r11, r8, lsl #2]

	// current allocation
	// r0 -
	// r1 -
	// r2 - s02 |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s31T // c2 ror24
	// r5 - s01T ^ s23T ^ s30T // c1
	// r6 - s12 // c1 ror8
	// r7 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r8 - s21T // c3 ror0
	// r9 - s10T // c3 ror8
	// r10 - s20T // c2 ror0

	eor.w r10, r10, r4, ror #24
	ldr r6, [r11, r6, lsl #2]

	uxtb r4, r2
	ldrd r0,r1, [r12], #8 // load rk

	// current allocation
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 -  -  |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s02 // c2 ror16
	// r5 - s01T ^ s23T ^ s30T // c1
	// r6 - s12T // c1 ror8
	// r7 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r8 - s21T // c3 ror0
	// r9 - s10T // c3 ror8
	// r10 - s20T ^ s31T // c2

	eor.w r8, r8, r9, ror #8
	eor.w r5, r5, r6, ror #8

	uxtb r6, r3
	ldr r4, [r11, r4, lsl #2]

	// current allocation
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 -  -  |  -  |  -  | s32
	// r3 -  -  | s13 |  -  |  -
	// r4 - s02T // c2 ror16
	// r5 - s01T ^ s12T ^ s23T ^ s30T // c1
	// r6 - s03 // c3 ror16
	// r7 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r8 - s10T ^ s21T // c3
	// r9 -
	// r10 - s20T ^ s31T // c2

	ubfx r9, r3, #8, #8
	eor.w r10, r10, r4, ror #16

	lsrs r4, r2, #24
	ldr r6, [r11, r6, lsl #2]

	// current allocation
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 -
	// r3 -
	// r4 - s32 // c3 ror24
	// r5 - s01T ^ s12T ^ s23T ^ s30T // c1
	// r6 - s03T // c3 ror16
	// r7 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r8 - s10T ^ s21T // c3
	// r9 - s13 // c2 ror8
	// r10 - s02T ^ s20T ^ s31T // c2

	eors r0, r7
	ldr r9, [r11, r9, lsl #2]

	eor.w r6, r8, r6, ror #16
	ldr r4, [r11, r4, lsl #2]

	// current allocation
	// r0 - col 0
	// r1 - rk[1]
	// r2 -
	// r3 -
	// r4 - s32T // c3 ror24
	// r5 - s01T ^ s12T ^ s23T ^ s30T // c1
	// r6 - s03T ^ s10T ^ s21T // c3
	// r7 -
	// r8 -
	// r9 - s13T // c2 ror8
	// r10 - s02T ^ s20T ^ s31T // c2

	eor.w r7, r10, r9, ror #8
	ldrd r2,r3, [r12], #8 // load rk

	// current allocation
	// r0 - col 0
	// r1 - rk[1]
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 - s32T // c3 ror24
	// r5 - s01T ^ s12T ^ s23T ^ s30T // c1
	// r6 - s03T ^ s10T ^ s21T // c3
	// r7 - s02T ^ s13T ^ s20T ^ s31T // c2
	// r8 -
	// r9 -
	// r10 -

	eor.w r6, r6, r4, ror #24
	eors r1, r5

	eors r2, r7
	eors r3, r6
	le lr, 1b

	// final round
	uxtb r4, r0
	lsrs r5, r0, #24

	ubfx r8, r1, #8, #8
	ubfx r9, r2, #16, #8

	// current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 - s01 |  -  | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 | s23 | s33
	// r4 - s00 // r0c0
	// r5 - s30 // r3c1
	// r6 -
	// r7 -
	// r8 - s11 // r1c0
	// r9 - s22 // r2c0
	// r10 -
	// r14 -

	ldrb r4, [r11, r4, lsl #2]
	uxtb r6, r1

	ldrb r5, [r11, r5, lsl #2]
	lsrs r7, r3, #24

	// current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 | s23 |  -
	// r4 - s00` // r0c0
	// r5 - s30` // r3c1
	// r6 - s01 // r0c1
	// r7 - s33 // r3c0
	// r8 - s11 // r1c0
	// r9 - s22 // r2c0
	// r10 -
	// r14 -

	ldrb r8, [r11, r8, lsl #2]
	ubfx r10, r2, #8, #8

	ldrb r9, [r11, r9, lsl #2]
	ubfx r14, r3, #16, #8

	// current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00` // r0c0
	// r5 - s30` // r3c1
	// r6 - s01 // r0c1
	// r7 - s33 // r3c0
	// r8 - s11` // r1c0
	// r9 - s22` // r2c0
	// r10 - s12 // r1c1
	// r14 - s23 // r2c1

	ldrb r6, [r11, r6, lsl #2]
	orr.w r4, r4, r8, lsl #8

	ldrb r7, [r11, r7, lsl #2]
	orr.w r9, r4, r9, lsl #16

	// current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 -
	// r5 - s30` // r3c1
	// r6 - s01` // r0c1
	// r7 - s33` // r3c0
	// r8 -
	// r9 - s00`| s11`| s22`|
	// r10 - s12 // r1c1
	// r14 - s23 // r2c1

	ldrb r10, [r11, r10, lsl #2]
	uxtb r4, r2

	ldrb r14, [r11, r14, lsl #2]
	orr.w r6, r6, r5, lsl #24

	// current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 -  -  |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s02 // r0c2
	// r5 -
	// r6 - s01`|     |     | s30`
	// r7 - s33` // r3c0
	// r8 -
	// r9 - s00`| s11`| s22`|
	// r10 - s12` // r1c1
	// r14 - s23` // r2c1

	lsrs r5, r1, #24
	ubfx r8, r0, #16, #8

	ldrb r4, [r11, r4, lsl #2]
	orr.w r6, r6, r10, lsl #8

	// current allocation
	// r0 -  -  | s10 |  -  |  -
	// r1 -  -  |  -  | s21 |  -
	// r2 -  -  |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s02` // r0c2
	// r5 - s31 // r3c2
	// r6 - s01`| s12`|     | s30`
	// r7 - s33` // r3c0
	// r8 - s20 // r2c2
	// r9 - s00`| s11`| s22`|
	// r10 -
	// r14 - s23` // r2c1

	ldrb r5, [r11, r5, lsl #2]
	ubfx r10, r0, #8, #8

	ldrb r8, [r11, r8, lsl #2]
	orr.w r7, r9, r7, lsl #24

	// current allocation
	// r0 -
	// r1 -  -  |  -  | s21 |  -
	// r2 -  -  |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s02` // r0c2
	// r5 - s31` // r3c2
	// r6 - s01`| s12`|     | s30`
	// r7 - s00`| s11`| s22`| s33
	// r8 - s20` // r2c2
	// r9 -
	// r10 - s10 // r1c3
	// r14 - s23` // r2c1

	orr.w r5, r4, r5, lsl #24
	ubfx r9, r1, #16, #8

	ldrd r0,r1, [r12], #8
	orr.w r6, r6, r14, lsl #16

	// current allocation
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 -  -  |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 -
	// r5 - s02`|     |     | s31`
	// r6 - s01`| s12`| s23`| s30`
	// r7 - s00`| s11`| s22`| s33
	// r8 - s20` // r2c2
	// r9 - s21 // r2c3
	// r10 - s10 // r1c3
	// r14 -

	ldrb r10, [r11, r10, lsl #2]
	uxtb r4, r3

	ldrb r9, [r11, r9, lsl #2]
	eors r0, r7

	// current allocation
	// r0 - col 0
	// r1 - rk[1]
	// r2 -  -  |  -  |  -  | s32
	// r3 -  -  | s13 |  -  |  -
	// r4 - s03 // r0c3
	// r5 - s02`|     |     | s31`
	// r6 - s01`| s12`| s23`| s30`
	// r7 -
	// r8 - s20` // r2c2
	// r9 - s21` // r2c3
	// r10 - s10` // r1c3
	// r14 -

	lsrs r7, r2, #24
	orr.w r5, r5, r8, lsl #16

	ldrb r4, [r11, r4, lsl #2]
	ubfx r8, r3, #8, #8

	// current allocation
	// r0 - col 0
	// r1 - rk[1]
	// r2 -
	// r3 -
	// r4 - s03` // r0c3
	// r5 - s02`|     | s20`| s31`
	// r6 - s01`| s12`| s23`| s30`
	// r7 - s32 // r3c3
	// r8 - s13 // r1c2
	// r9 - s21` // r2c3
	// r10 - s10` // r1c3
	// r14 -

	ldrb r7, [r11, r7, lsl #2]
	orr.w r10, r4, r10, lsl #8

	ldrb r8, [r11, r8, lsl #2]
	orr.w r10, r10, r9, lsl #16

	// current allocation
	// r0 - col 0
	// r1 - rk[1]
	// r2 -
	// r3 -
	// r4 -
	// r5 - s02`|     | s20`| s31`
	// r6 - s01`| s12`| s23`| s30`
	// r7 - s32` // r3c3
	// r8 - s13` // r1c2
	// r9 -
	// r10 - s03`| s10`| s21`|
	// r14 -

	ldrd r14,r4, [sp], #8 // EX1 EX2
	eors r1, r6

	ldrd r2,r3, [r12]
	strd r0,r1, [r14], #8 // EX2

	// current allocation
	// r0 -
	// r1 -
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 - unstacked
	// r5 - s02`|     | s20`| s31`
	// r6 -
	// r7 - s32` // r3c3
	// r8 - s13` // r1c2
	// r9 -
	// r10 - s03`| s10`| s21`|
	// r14 - out_p

	orr.w r0, r5, r8, lsl #8
	orr.w r1, r10, r7, lsl #24

	ldrd r5,r6, [sp], #8
	eors r2, r0

	// current allocation
	// r0 -
	// r1 - s03`| s10`| s21`| s32`
	// r2 - col 2
	// r3 - rk[3]
	// r4 - unstacked
	// r5 - unstacked
	// r6 - unstacked
	// r7 -
	// r8 -
	// r9 -
	// r10 -
	// r14 - out_p

	ldrd r7,r8, [sp], #8
	eors r3, r1

	ldrd r9,r10, [sp], #8
	strd r2,r3, [r14]

	// cycle faster than pop(pc) or loading anything but lr
	ldrd r11,lr, [sp], #8
	bx lr

#endif
