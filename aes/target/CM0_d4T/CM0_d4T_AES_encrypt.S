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

	// using sbox is ~10 cycles faster, currently recycling keyschedules
	//sbox 64x +2(3)
	//d4t 77x +1

	ldr r0, =AES_sbox
	mov r9, r0 // AES_sbox

	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 | s33

	//final
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02`| s13`| s20`| s31`
	// r7 - s03`| s10`| s21`| s32`

	lsrs r1, r7, #24
	ldrb r1, [r0, r1]
	lsls r1, #24

	rev16 r3, r5

	// r0 - sbox
	// r1 -                   s33`
	// r2 -
	// r3 - s11 |  -  |  -  | s21

	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 |  -

	uxtb r2, r3
	ldrb r2, [r0, r2]
	lsls r2, #8

	orrs r1, r2

	rev16 r2, r7
	uxtb r7, r7
	ldrb r7, [r0, r7]

	// r0 - sbox
	// r1 -     | s11`|     | s33`
	// r2 - s13 |  -  |  -  | s23
	// r3 -  -  |  -  |  -  | s21

	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03`|     |     |

	lsrs r3, #24
	ldrb r3, [r0, r3]
	lsls r3, #16

	orrs r7, r3

	// r0 - sbox
	// r1 -     | s11`|     | s33`
	// r2 - s13 |  -  |  -  | s23
	// r3 -

	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03`|     | s21`|

	lsrs r3, r6, #24
	ldrb r3, [r0, r3]
	lsls r3, #24

	orrs r7, r3

	// r0 - sbox
	// r1 -     | s11`|     | s33`
	// r2 - s13 |  -  |  -  | s23
	// r3 -

	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02 | s12 | s22 |  -
	// r7 - s03`|     | s21`| s32`

	//give up on rev16

	lsrs r3, r6, #16
	uxtb r3, r3
	ldrb r3, [r0, r3]
	lsls r3, #16

	orrs r1, r3

	// r0 - sbox
	// r1 -     | s11`| s22`| s33`
	// r2 - s13 |  -  |  -  | s23
	// r3 -

	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02 | s12 |  -  |  -
	// r7 - s03`|     | s21`| s32`

	//give up on rev16 // column 0 goes into r3

	uxtb r3, r4
	ldrb r3, [r0, r3]

	orrs r3, r1

	lsrs r1, r4, #8
	uxtb r1, r1
	ldrb r1, [r0, r1]
	lsls r1, #8

	orrs r7, r1

	// r0 - sbox
	// r1 -
	// r2 - s13 |  -  |  -  | s23
	// r3 - s00`| s11`| s22`| s33`

	// r4 -  -  |  -  | s20 | s30
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02 | s12 |  -  |  -
	// r7 - s03`| s10`| s21`| s32`

	lsrs r1, r4, #24
	ldrb r1, [r0, r1]
	lsls r1, #24

	lsrs r4, #16
	uxtb r4, r4
	ldrb r4, [r0, r4]
	lsls r4, #16

	// r0 - sbox
	// r1 -     |     |     | s30`
	// r2 - s13 |  -  |  -  | s23
	// r3 - s00`| s11`| s22`| s33`

	// r4 -     |     | s20`|
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02 | s12 |  -  |  -
	// r7 - s03`| s10`| s21`| s32`

	lsrs r0, r5, #24 // too high pressure

	uxtb r5, r5
	add r5, r9 // add sbox base
	ldrb r5, [r5]

	orrs r5, r1

	mov r1, r9 // get sbox back
	ldrb r0, [r1, r0]
	lsls r0, #24

	// r0 -     |     |     | s31`
	// r1 - sbox
	// r2 - s13 |  -  |  -  | s23
	// r3 - s00`| s11`| s22`| s33`

	// r4 -     |     | s20`|
	// r5 - s01`|     |     | s30`
	// r6 - s02 | s12 |  -  |  -
	// r7 - s03`| s10`| s21`| s32`

	orrs r4, r0

	lsrs r0, r2, #24
	ldrb r0, [r1, r0]
	lsls r0, #16

	orrs r5, r0

	// r0 -
	// r1 - sbox
	// r2 - s13 |  -  |  -  |  -
	// r3 - s00`| s11`| s22`| s33`

	// r4 -     |     | s20`| s31`
	// r5 - s01`|     | s23`| s30`
	// r6 - s02 | s12 |  -  |  -
	// r7 - s03`| s10`| s21`| s32`

	uxtb r2, r2
	ldrb r2, [r1, r2]
	lsls r2, #8

	lsrs r0, r6, #8
	uxtb r0, r0
	ldrb r0, [r1, r0]
	lsls r0, #8

	orrs r5, r0

	// r0 -
	// r1 - sbox
	// r2 -     | s13`|     |
	// r3 - s00`| s11`| s22`| s33`

	// r4 -     |     | s20`| s31`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02 |  -  |  -  |  -
	// r7 - s03`| s10`| s21`| s32`

	uxtb r6, r6
	ldrb r6, [r1, r6]

	orrs r6, r2
	orrs r6, r4

	// r3 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02`| s13`| s20`| s31`
	// r7 - s03`| s10`| s21`| s32`

	//mov r4, r3 // positioning fixed in epilogue

	//final addroundkey
	mov r0, r14 // get current rk

	ldm r0, {r0-r2, r4}
	eors r3, r0
	eors r5, r1
	eors r6, r2
	eors r7, r4

	pop {r0-r1, r4} // pop to non data // unstack also out pointer
	mov r8, r0
	mov r9, r1

	stmia r4!, {r3,r5-r7}


	pop {r4-r7, pc}

#endif
