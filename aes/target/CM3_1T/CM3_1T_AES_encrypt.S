/*!
 * \file CM3_1T_AES_encrypt.S
 * \brief cortex-m3/4 optimized aes encryption
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
// void CM3_1T_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM3_1T_AES_encrypt
.type   CM3_1T_AES_encrypt,%function
CM3_1T_AES_encrypt:
	push {r2,r4-r11,lr} //stack out
	add r11, r0, r3, lsl #4 //rk_end-16 = rk + rounds * 16

	movw r14, #:lower16:AES_Te2
	movt r14, #:upper16:AES_Te2

	mov r12, r0

	//load input
	ldmia r1!, {r4-r7}
	//load key
	ldmia r12!, {r0-r3}

	//initial addroundkey
	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

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

1:	uxtb r4, r0
	lsrs r6, r3, #24
	uxtb.w r9, r1, ror #8
	uxtb.w r10, r2, ror #16
	uxtb.w r8, r3, ror #16
	uxtb r5, r1
	lsrs r7, r0, #24

	ldr.w r4, [r14, r4, lsl #2]
	ldr.w r6, [r14, r6, lsl #2]
	ldr.w r9, [r14, r9, lsl #2]
	ldr.w r10, [r14, r10, lsl #2]
	ldr.w r8, [r14, r8, lsl #2]
	ldr.w r5, [r14, r5, lsl #2]
	ldr.w r7, [r14, r7, lsl #2]

	//current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00T // c0 ror16
	// r5 - s01T // c1 ror16
	// r6 - s33T // c0 ror24
	// r7 - s30T // c1 ror24
	// r8 - s23T // c1 ror0
	// r9 - s11T // c0 ror8
	// r10 - s22T // c0 ror0

	eor.w r4, r10, r4, ror #16
	eor.w r4, r4, r9, ror #8
	eor.w r4, r4, r6, ror #24
	eor.w r5, r8, r5, ror #16
	eor.w r5, r5, r7, ror #24

	uxtb r6, r2
	uxtb r7, r3
	uxtb.w r8, r0, ror #16
	uxtb.w r9, r2, ror #8
	uxtb.w r10, r1, ror #16
	uxtb.w r3, r3, ror #8
	uxtb.w r0, r0, ror #8
	lsrs r1, r1, #24
	lsrs r2, r2, #24

	ldr.w r6, [r14, r6, lsl #2]
	ldr.w r7, [r14, r7, lsl #2]
	ldr.w r8, [r14, r8, lsl #2]
	ldr.w r9, [r14, r9, lsl #2]
	ldr.w r10, [r14, r10, lsl #2]
	ldr.w r3, [r14, r3, lsl #2]
	ldr.w r0, [r14, r0, lsl #2]
	ldr.w r1, [r14, r1, lsl #2]
	ldr.w r2, [r14, r2, lsl #2]

	//current allocation
	// r0 - s10T // c3 ror8
	// r1 - s31T // c2 ror24
	// r2 - s32T // c2 ror24
	// r3 - s13T // c2 ror8
	// r4 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r5 - s01T ^ s23T ^ s30T // c1
	// r6 - s02T // c2 ror16
	// r7 - s03T // c3 ror16
	// r8 - s20T // c2 ror0
	// r9 - s12T // c1 ror8
	// r10 - s21T // c3 ror0

	eor.w r5, r5, r9, ror #8
	eor.w r6, r8, r6, ror #16
	eor.w r7, r10, r7, ror #16
	eor.w r6, r6, r3, ror #8
	eor.w r7, r7, r0, ror #8
	eor.w r6, r6, r1, ror #24
	eor.w r7, r7, r2, ror #24

	ldmia.w r12!, {r0-r3} // load rk

	//current allocation
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r5 - s01T ^ s12T ^ s23T ^ s30T // c1
	// r6 - s02T ^ s13T ^ s20T ^ s31T // c2
	// r7 - s03T ^ s10T ^ s21T ^ s32T // c3
	// r8 -
	// r9 -
	// r10 -

	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	cmp r11, r12
	bne 1b

	//final round

	// r0 - s00 | s10 | s20 | s30
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33

	//final
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02`| s13`| s20`| s31`
	// r7 - s03`| s10`| s21`| s32`

	uxtb r4, r0
	lsrs r6, r3, #24
	uxtb.w r9, r1, ror #8
	uxtb.w r10, r2, ror #16
	uxtb.w r8, r3, ror #16
	uxtb r5, r1
	lsrs r7, r0, #24

	ldrb.w r4, [r14, r4, lsl #2]
	ldrb.w r6, [r14, r6, lsl #2]
	ldrb.w r9, [r14, r9, lsl #2]
	ldrb.w r10, [r14, r10, lsl #2]
	ldrb.w r8, [r14, r8, lsl #2]
	ldrb.w r5, [r14, r5, lsl #2]
	ldrb.w r7, [r14, r7, lsl #2]

	//current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00` // c0r0
	// r5 - s01` // c1r0
	// r6 - s33` // c0r3
	// r7 - s30` // c1r3
	// r8 - s23` // c1r2
	// r9 - s11` // c0r1
	// r10 - s22` // c0r2

	orr.w r4, r4, r6, lsl #24
	orr.w r4, r4, r9, lsl #8
	orr.w r4, r4, r10, lsl #16
	orr.w r5, r5, r8, lsl #16
	orr.w r5, r5, r7, lsl #24

	uxtb r6, r2
	uxtb r7, r3
	uxtb.w r8, r0, ror #16
	uxtb.w r9, r2, ror #8
	uxtb.w r10, r1, ror #16
	uxtb.w r3, r3, ror #8
	uxtb.w r0, r0, ror #8
	lsrs r1, r1, #24
	lsrs r2, r2, #24

	ldrb.w r6, [r14, r6, lsl #2]
	ldrb.w r7, [r14, r7, lsl #2]
	ldrb.w r8, [r14, r8, lsl #2]
	ldrb.w r9, [r14, r9, lsl #2]
	ldrb.w r10, [r14, r10, lsl #2]
	ldrb.w r3, [r14, r3, lsl #2]
	ldrb.w r0, [r14, r0, lsl #2]
	ldrb.w r1, [r14, r1, lsl #2]
	ldrb.w r2, [r14, r2, lsl #2]

	//current allocation
	// r0 - s10` // c3r1
	// r1 - s31` // c2r3
	// r2 - s32` // c3r3
	// r3 - s13` // c2r1
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`|     | s23`| s30`
	// r6 - s02` // c2r0
	// r7 - s03` // c3r0
	// r8 - s20` // c2r2
	// r9 - s12` // c1r1
	// r10 - s21` // c3r2

	orr.w r5, r5, r9, lsl #8
	orr.w r6, r6, r8, lsl #16
	orr.w r7, r7, r10, lsl #16
	orr.w r6, r6, r3, lsl #8
	orr.w r7, r7, r0, lsl #8
	orr.w r6, r6, r1, lsl #24
	orr.w r7, r7, r2, lsl #24

	ldr r8, [sp], #4 // load output pointer and clear stack
	ldr r0, [r12, #0]
	ldr r1, [r12, #4]
	ldr r2, [r12, #8]
	ldr r3, [r12, #12]

	//current allocation
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02`| s13`| s20`| s31`
	// r7 - s03`| s10`| s21`| s32`
	// r8 - out p
	// r9 -
	// r10 -

	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	stmia.w r8!, {r0-r3}

	pop {r4-r11,pc}

#endif
