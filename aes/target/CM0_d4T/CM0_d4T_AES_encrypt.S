/*!
 * \file CM0_d4T_AES_encrypt.S
 * \brief
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only
#if __ARM_EABI__

.syntax unified
.thumb
.text

.balign 4
// void CM0_d4T_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM0_d4T_AES_encrypt
.type   CM0_d4T_AES_encrypt,%function
CM0_d4T_AES_encrypt:
	push {r2, r4-r7, lr} // stack out ptr (faster than pressure on upper regs)
	mov r4, r8
	mov r5, r9
	push {r4-r5}

	movs r4, #16
	mov r8, r4

	ldr r7, =AES_d4Te
	mov r9, r7 // AES_d4Te

	//rk_end-16 = rk + rounds * 16
	lsls r3, #4
	adds r3, r0
	mov r12, r3 // final ptr

	ldmia r0!, {r4-r7} // load key
	mov r14, r0 // already incremented

	ldm r1, {r0-r3} // load input

	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	// global allocation
	// r8 - increment constant
	// r9 - AES_d4Te
	// r10 - x
	// r11 - x
	// r12 - final ptr
	// r14 - current ptr

	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 | s33

	// row offset into d4T
	// xor   0 |  4  |  8  |  12

	//final
	// r0 - s00T ^ s11T ^ s22T ^ s33T
	// r1 - s01T ^ s12T ^ s23T ^ s30T
	// r2 - s02T ^ s13T ^ s20T ^ s31T
	// r3 - s03T ^ s10T ^ s21T ^ s32T

.balign 4
1:
	mov r3, r9 // skip 3 additions on row0

	uxtb r0, r4
	lsls r0, #4
	ldr r0, [r3, r0]

	uxtb r1, r5
	lsls r1, #4
	ldr r1, [r3, r1]

	uxtb r2, r6
	lsls r2, #4
	ldr r2, [r3, r2]

	//current allocaton
	// r0 - s00T
	// r1 - s01T
	// r2 - s02T
	// r3 - AES_d4Te
	// r4 -  -  | s10 | s20 | s30
	// r5 -  -  | s11 | s21 | s31
	// r6 -  -  | s12 | s22 | s32
	// r7 - s03 | s13 | s23 | s33

	lsrs r3, r7, #24
	lsls r3, #4
	add r3, r9
	ldr r3, [r3, #12]

	eors r0, r3

	lsrs r3, r4, #24
	lsls r3, #4
	add r3, r9
	ldr r3, [r3, #12]

	eors r1, r3

	lsrs r3, r5, #24
	lsls r3, #4
	add r3, r9
	ldr r3, [r3, #12]

	eors r2, r3

	//current allocaton
	// r0 - s00T ^ s33T
	// r1 - s01T ^ s30T
	// r2 - s02T ^ s31T
	// r3 -
	// r4 -  -  | s10 | s20 |  -
	// r5 -  -  | s11 | s21 |  -
	// r6 -  -  | s12 | s22 | s32
	// r7 - s03 | s13 | s23 |  -

	rev16 r4, r4
	rev16 r5, r5

	//current allocaton
	// r0 - s00T ^ s33T
	// r1 - s01T ^ s30T
	// r2 - s02T ^ s31T
	// r3 -
	// r4 - s10 |  -  |  -  | s20
	// r5 - s11 |  -  |  -  | s21
	// r6 -  -  | s12 | s22 | s32
	// r7 - s03 | s13 | s23 |  -

	lsrs r3, r4, #24
	lsls r3, #4
	add r3, r9
	ldr r3, [r3, #8]

	eors r2, r3

	uxtb r3, r5
	lsls r3, #4
	add r3, r9
	ldr r3, [r3, #4]

	eors r0, r3

	//current allocaton
	// r0 - s00T ^ s11T ^ s33T
	// r1 - s01T ^ s30T
	// r2 - s02T ^ s20T ^ s31T
	// r3 -
	// r4 - s10 |  -  |  -  |  -
	// r5 -  -  |  -  |  -  | s21
	// r6 -  -  | s12 | s22 | s32
	// r7 - s03 | s13 | s23 |  -

	uxtb r3, r7
	lsls r3, #4
	add r3, r9
	ldr r3, [r3, #0]

	uxtb r4, r4
	lsls r4, #4
	add r4, r9
	ldr r4, [r4, #4]

	eors r3, r4

	//current allocaton
	// r0 - s00T ^ s11T ^ s33T
	// r1 - s01T ^ s30T
	// r2 - s02T ^ s20T ^ s31T
	// r3 - s03T ^ s10T
	// r4 -
	// r5 -  -  |  -  |  -  | s21
	// r6 -  -  | s12 | s22 | s32
	// r7 -  -  | s13 | s23 |  -

	lsrs r4, r5, #24
	lsls r4, #4
	add r4, r9
	ldr r4, [r4, #8]

	eors r3, r4

	lsrs r4, r6, #24
	lsls r4, #4
	add r4, r9
	ldr r4, [r4, #12]

	eors r3, r4

	//current allocaton
	// r0 - s00T ^ s11T ^ s33T
	// r1 - s01T ^ s30T
	// r2 - s02T ^ s20T ^ s31T
	// r3 - s03T ^ s10T ^ s21T ^ s32
	// r4 -
	// r5 -
	// r6 -  -  | s12 | s22 |  -
	// r7 -  -  | s13 | s23 |  -

	rev16 r6, r6
	rev16 r7, r7

	//current allocaton
	// r0 - s00T ^ s11T ^ s33T
	// r1 - s01T ^ s30T
	// r2 - s02T ^ s20T ^ s31T
	// r3 - s03T ^ s10T ^ s21T ^ s32T
	// r4 -
	// r5 -
	// r6 - s12 |  -  |  -  | s22
	// r7 - s13 |  -  |  -  | s23

	uxtb r4, r6
	lsls r4, #4
	add r4, r9
	ldr r4, [r4, #4]

	eors r1, r4

	lsrs r4, r6, #24
	lsls r4, #4
	add r4, r9
	ldr r4, [r4, #8]

	eors r0, r4

	//current allocaton
	// r0 - s00T ^ s11T ^ s22T ^ s33T
	// r1 - s01T ^ s12T ^ s30T
	// r2 - s02T ^ s20T ^ s31T
	// r3 - s03T ^ s10T ^ s21T ^ s32T
	// r4 -
	// r5 -
	// r6 -
	// r7 - s13 |  -  |  -  | s23

	uxtb r4, r7
	lsls r4, #4
	add r4, r9
	ldr r4, [r4, #4]

	eors r2, r4

	lsrs r4, r7, #24
	lsls r4, #4
	add r4, r9
	ldr r4, [r4, #8]

	eors r1, r4

	//current allocaton
	// r0 - s00T ^ s11T ^ s22T ^ s33T
	// r1 - s01T ^ s12T ^ s23T ^ s30T
	// r2 - s02T ^ s13T ^ s20T ^ s31T
	// r3 - s03T ^ s10T ^ s21T ^ s32T
	// r4 -
	// r5 -
	// r6 -
	// r7 -

	//addroundkey
	mov r7, r14 // get current rk
	add r14, r8 // increment rk by 16

	ldm r7, {r4-r7}
	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	cmp r14, r12
	bne 1b // if rk reached final condition

	//final round

	// sbox is at
	// bank1 - +1 +2
	// bank2 - +6 +7
	// bank3 - +8 +11
	// bank4 - +12 +13

	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 | s33

	//final
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02`| s13`| s20`| s31`
	// r7 - s03`| s10`| s21`| s32`

	movs r3, #6 // bank 2
	add r3, r9

	uxtb r0, r4
	lsls r0, #4
	ldrb r0, [r3, r0]

	lsrs r1, r7, #24
	lsls r1, #4
	ldrb r1, [r3, r1]
	lsls r1, #24

	orrs r0, r1

	//current allocaton
	// r0 - s00`|     |     | s33`
	// r1 -
	// r2 -
	// r3 - AES_d4Te + 6
	// r4 -  -  | s10 | s20 | s30
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 |  -

	rev16 r2, r6

	lsrs r1, r2, #24
	lsls r1, #4
	ldrb r1, [r3, r1]
	lsls r1, #16

	orrs r0, r1

	uxtb r2, r2
	lsls r2, #4
	ldrb r2, [r3, r2]
	lsls r2, #8

	uxtb r1, r5
	lsls r1, #4
	ldrb r1, [r3, r1]

	orrs r1, r2

	//current allocaton
	// r0 - s00`|     | s22`| s33`
	// r1 - s01`| s12`|     |
	// r2 -
	// r3 - AES_d4Te + 6
	// r4 -  -  | s10 | s20 | s30
	// r5 -  -  | s11 | s21 | s31
	// r6 - s02 |  -  |  -  | s32
	// r7 - s03 | s13 | s23 |  -

	lsrs r2, r4, #24
	lsls r2, #4
	ldrb r2, [r3, r2]
	lsls r2, #24

	orrs r1, r2

	uxtb r2, r6
	lsls r2, #4
	ldrb r2, [r3, r2]

	//current allocaton
	// r0 - s00`|     | s22`| s33`
	// r1 - s01`| s12`|     | s30`
	// r2 - s02`|     |     |
	// r3 - AES_d4Te + 6
	// r4 -  -  | s10 | s20 |  -
	// r5 -  -  | s11 | s21 | s31
	// r6 -  -  |  -  |  -  | s32
	// r7 - s03 | s13 | s23 |  -

	lsrs r6, #24
	lsls r6, #4
	ldrb r6, [r3, r6]
	lsls r6, #24

	rev16 r4, r4

	uxtb r3, r4 // too high pressure
	lsls r3, #4
	add r3, r9 // pointer spilled
	ldrb r3, [r3, #8] // use different bank now
	lsls r3, #8

	orrs r3, r6

	//current allocaton
	// r0 - s00`|     | s22`| s33`
	// r1 - s01`| s12`|     | s30`
	// r2 - s02`|     |     |
	// r3 -     | s10`|     | s32`
	// r4 -  -  |  -  |  -  | s20
	// r5 -  -  | s11 | s21 | s31
	// r6 -
	// r7 - s03 | s13 | s23 |  -

	movs r6, #8 // bank 3 (or bank 1 on dual banked)
	add r6, r9

	lsrs r4, #24
	lsls r4, #4
	ldrb r4, [r6, r4]
	lsls r4, #16

	orrs r2, r4

	//current allocaton
	// r0 - s00`|     | s22`| s33`
	// r1 - s01`| s12`|     | s30`
	// r2 - s02`|     | s20`|
	// r3 -     | s10`|     | s32`
	// r4 -
	// r5 -  -  | s11 | s21 | s31
	// r6 - AES_d4Te + 8
	// r7 - s03 | s13 | s23 |  -

	uxtb r4, r7
	lsls r4, #4
	ldrb r4, [r6, r4]

	orrs r3, r4

	lsrs r4, r5, #24
	lsls r4, #4
	ldrb r4, [r6, r4]
	lsls r4, #24

	orrs r2, r4

	//current allocaton
	// r0 - s00`|     | s22`| s33`
	// r1 - s01`| s12`|     | s30`
	// r2 - s02`|     | s20`| s31`
	// r3 - s03`| s10`|     | s32`
	// r4 -
	// r5 -  -  | s11 | s21 |  -
	// r6 - AES_d4Te + 8
	// r7 -  -  | s13 | s23 |  -

	rev16 r5, r5

	uxtb r4, r5
	lsls r4, #4
	ldrb r4, [r6, r4]
	lsls r4, #8

	orrs r0, r4

	lsrs r5, #24
	lsls r5, #4
	ldrb r5, [r6, r5]
	lsls r5, #16

	orrs r3, r5

	//current allocaton
	// r0 - s00`| s11`| s22`| s33`
	// r1 - s01`| s12`|     | s30`
	// r2 - s02`|     | s20`| s31`
	// r3 - s03`| s10`| s21`| s32`
	// r4 -
	// r5 -
	// r6 - AES_d4Te + 8
	// r7 -  -  | s13 | s23 |  -

	rev16 r7, r7

	uxtb r4, r7
	lsls r4, #4
	ldrb r4, [r6, r4]
	lsls r4, #8

	orrs r2, r4

	lsrs r7, #24
	lsls r7, #4
	ldrb r7, [r6, r7]
	lsls r7, #16

	orrs r1, r7

	//current allocaton
	// r0 - s00`| s11`| s22`| s33`
	// r1 - s01`| s12`| s23`| s30`
	// r2 - s02`| s13`| s20`| s31`
	// r3 - s03`| s10`| s21`| s32`
	// r4 -
	// r5 -
	// r6 - AES_d4Te + 8
	// r7 -

	//final addroundkey
	mov r7, r14 // get current rk

	ldm r7, {r4-r7}
	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	pop {r0-r1, r2} // pop to non data // unstack also out pointer
	mov r8, r0
	mov r9, r1

	stmia r2!, {r4-r7}

	pop {r4-r7, pc}

#endif
