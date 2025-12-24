/*!
 * \file CM33_d4T_AES_encrypt.S
 * \brief cortex-m33 optimized aes encryption
 *
 * Utilizes diffused 4 Te tables, which protects from bank timming attacks, as each
 * data dependent lookup can hit only within one bank.
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
// void CM33_d4T_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM33_d4T_AES_encrypt
.type   CM33_d4T_AES_encrypt,%function
CM33_d4T_AES_encrypt:
	//rk_end-16 = rk + rounds * 16
	lsls r3, #4
	adds r3, r0

	push {r2,r3,r4-r11,lr} // stack out and final ptr

	movw r8, #:lower16:AES_d4Te
	movt r8, #:upper16:AES_d4Te

	// generate extraction mask, preshifted by 4 as to avoid separate scaling step
	movw r14, #0x00000ff0

	ldmia r1!, {r4-r7} // load input

	// precalc pointers with offsets as we need to use reg offset loads
	add r9, r8, #4 // d4Te + 4
	add r10, r9, #4 // d4Te + 8
	add r11, r10, #4 // d4Te + 12

	mov r12, r0

	ldmia r12!, {r0-r3} // load key

	// initial addroundkey
	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	// sp
	// +0 - out
	// +4 - final ptr

	// global allocation
	// r8 - d4Te + 0
	// r9 - d4Te + 4
	// r10 - d4Te + 8
	// r11 - d4Te + 12
	// r12 - current rk ptr
	// r14 - 0x00000ff0 (extract mask)

	// state elements will be represented with big endian order (transposed canonical state representation)
	// columns are loaded in little endian so right/left in shifts is in reverse wrt transposed canonical state representation

	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 | s33

	// extraction shift amount (applying scaling in this step)
	// lsr  -4  |  4  |  12 |  20

	// row offset into d4T
	// xor   0 |  4  |  8  |  12

	//final
	// r0 - s00T ^ s11T ^ s22T ^ s33T
	// r1 - s01T ^ s12T ^ s23T ^ s30T
	// r2 - s02T ^ s13T ^ s20T ^ s31T
	// r3 - s03T ^ s10T ^ s21T ^ s32T

1:
	//current allocation
	// r0 - s00 | s10 | s20 | s30
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33
	// r4 -
	// r5 -
	// r6 -
	// r7 -

	and.w r4, r14, r0, lsl #4
	and.w r5, r14, r1, lsr #4
	and.w r6, r14, r2, lsr #12
	and.w r7, r14, r3, lsr #20

	ldr.w r4, [r8, r4]
	ldr.w r5, [r9, r5]
	ldr.w r6, [r10, r6]
	ldr.w r7, [r11, r7]

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 - s01 |  -  | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 | s23 |  -
	// r4 - s00T
	// r5 - s11T
	// r6 - s22T
	// r7 - s33T

	eors r4, r5
	eors r4, r6
	eors r4, r7

	and.w r5, r14, r1, lsl #4
	and.w r6, r14, r2, lsr #4
	and.w r7, r14, r3, lsr #12

	ldr.w r5, [r8, r5]
	ldr.w r6, [r9, r6]
	ldr.w r7, [r10, r7]

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00T ^ s11T ^ s22T ^ s33T
	// r5 - s01T
	// r6 - s12T
	// r7 - s23T

	eors r5, r6
	eors r5, r7

	and.w r7, r14, r0, lsr #20
	and.w r6, r14, r2, lsl #4

	ldr.w r7, [r11, r7]
	ldr.w r6, [r8, r6]

	//current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 -  -  |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00T ^ s11T ^ s22T ^ s33T
	// r5 - s01T ^ s12T ^ s23T
	// r6 - s02T
	// r7 - s30T

	eors r5, r7

	and.w r7, r14, r3, lsr #4
	and.w r3, r14, r3, lsl #4
	and.w r2, r14, r2, lsr #20

	ldr.w r7, [r9, r7]
	ldr.w r3, [r8, r3]
	ldr.w r2, [r11, r2]

	//current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s32T
	// r3 - s03T
	// r4 - s00T ^ s11T ^ s22T ^ s33T
	// r5 - s01T ^ s12T ^ s23T ^ s30T
	// r6 - s02T
	// r7 - s13T

	eors r6, r7
	eors r3, r2

	and.w r2, r14, r0, lsr #12
	and.w r7, r14, r0, lsr #4

	ldr.w r2, [r10, r2]
	ldr.w r7, [r9, r7]

	//current allocation
	// r0 -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s20T
	// r3 - s03T ^ s32T
	// r4 - s00T ^ s11T ^ s22T ^ s33T
	// r5 - s01T ^ s12T ^ s23T ^ s30T
	// r6 - s02T ^ s13T
	// r7 - s10T

	eors r6, r2
	eors r7, r3

	and.w r2, r14, r1, lsr #20
	and.w r1, r14, r1, lsr #12

	ldr.w r2, [r11, r2]
	ldr.w r1, [r10, r1]

	eors r6, r2
	eors r7, r1

	//current allocation
	// r0 -
	// r1 -
	// r2 -
	// r3 -
	// r4 - s00T ^ s11T ^ s22T ^ s33T
	// r5 - s01T ^ s12T ^ s23T ^ s30T
	// r6 - s02T ^ s13T ^ s20T ^ s31T
	// r7 - s03T ^ s10T ^ s21T ^ s32T

	ldmia r12!, {r0-r3} // load rk

	eors r0, r4
	eors r1, r5
	ldr r4, [sp, #4] // load final cond
	eors r2, r6

	cmp r12, r4
	.short 0xbfe8 // it al (AL is 0b1110, required mask is 0b1000)
	// for some reason gcc doesn't accept `it` instruction with `al` condition
	// which is completely legal according to the architecture reference manual
	eors r3, r7 // actually eoral, condition flags not affected here
	bne 1b

	// final round

	// we need to address into d4Te, r10 and r11 already point to sbox
	// sbox is at:
	// bank1 - +1 +2
	// bank2 - +6 +7
	// bank3 - +8 +11
	// bank4 - +12 +13

	//current allocation
	// r0 - s00 | s10 | s20 | s30
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33
	// r4 -
	// r5 -
	// r6 -
	// r7 -

	//final
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02`| s13`| s20`| s31`
	// r7 - s03`| s10`| s21`| s32`

	and.w r4, r14, r0, lsl #4
	and.w r5, r14, r1, lsr #4
	and.w r6, r14, r2, lsr #12
	and.w r7, r14, r3, lsr #20

	ldrb.w r4, [r10, r4]
	ldrb.w r5, [r11, r5] // alternate access to reduce contention
	ldrb.w r6, [r10, r6]
	ldrb.w r7, [r11, r7]

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 - s01 |  -  | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 | s23 |  -
	// r4 - s00`
	// r5 - s11`
	// r6 - s22`
	// r7 - s33`

	bfi r4, r5, #8, #8
	bfi r4, r6, #16, #8
	bfi r4, r7, #24, #8

	and.w r5, r14, r1, lsl #4
	and.w r6, r14, r2, lsr #4
	and.w r7, r14, r3, lsr #12

	ldrb.w r5, [r10, r5]
	ldrb.w r6, [r11, r6]
	ldrb.w r7, [r10, r7]

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`
	// r6 - s12`
	// r7 - s23`

	bfi r5, r6, #8, #8
	bfi r5, r7, #16, #8

	and.w r7, r14, r0, lsr #20
	and.w r6, r14, r2, lsl #4

	ldrb.w r7, [r11, r7]
	ldrb.w r6, [r10, r6]

	//current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 -  -  |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`|
	// r6 - s02`
	// r7 - s30`

	bfi r5, r7, #24, #8

	and.w r7, r14, r3, lsr #4
	and.w r3, r14, r3, lsl #4
	and.w r2, r14, r2, lsr #20

	ldrb.w r7, [r11, r7]
	ldrb.w r3, [r10, r3]
	ldrb.w r2, [r11, r2]

	//current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s32`
	// r3 - s03`
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02`
	// r7 - s13`

	bfi r6, r7, #8, #8
	bfi r3, r2, #24, #8

	and.w r7, r14, r0, lsr #4
	and.w r2, r14, r0, lsr #12

	ldrb.w r7, [r10, r7]
	ldrb.w r2, [r11, r2]

	//current allocation
	// r0 -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s20`
	// r3 - s03`|     |     | s32`
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02`| s13`|     |
	// r7 - s10`

	orr.w r7, r3, r7, lsl #8 // need to move, latency is not an issue here
	bfi r6, r2, #16, #8

	and.w r2, r14, r1, lsr #20
	and.w r1, r14, r1, lsr #12

	ldrb.w r2, [r10, r2]
	ldrb.w r1, [r11, r1]

	bfi r6, r2, #24, #8
	bfi r7, r1, #16, #8

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
//595
	eors r4, r0 // need caller saved loreg for pointer
	eors r1, r5
	ldr r0, [sp], #8 // load out ptr
	eors r2, r6
	eors r3, r7

	str r4, [r0, #0]

	pop {r4-r11,lr}

	// store rest of the output
	str r1, [r0, #4]
	str r2, [r0, #8]
	str r3, [r0, #12]

	bx lr

#endif
