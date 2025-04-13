/*!
 * \file CM0_d4T_AES_decrypt.S
 * \brief cortex-m0 optimized aes decryption
 *
 * Utilizes diffused 4 Td and d4Td4 tables, which protects from bank timming
 * attacks on 4 banked (striped) SRAMS (e.g. SRAM0 on RP2040)
 *
 * requires backward expanded key
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
// void CM0_d4T_AES_decrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM0_d4T_AES_decrypt
.type   CM0_d4T_AES_decrypt,%function
CM0_d4T_AES_decrypt:
	push {r2, r4-r7, lr} // stack out ptr (faster than pressure on upper regs)
	mov r4, r8
	mov r5, r9
	push {r4-r5}

	ldr r7, =AES_d4Td
	mov r9, r7 // AES_d4Td

	movs r2, #16

	negs r4, r2 // hireg add will now subtract
	mov r8, r4 // rk decrementer

	adds r2, r0 // rk+16
	mov r12, r2 // final rk

	//create end, rk+0 + rounds * 16
	lsls r3, #4
	adds r0, r3
	mov r14, r0

	ldmia r0!, {r4-r7} // load key

	ldm r1, {r0-r3} // load input

	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	// state elements will be represented with big endian order (transposed canonical state representation)
	// columns are loaded in little endian so right/left in shifts is in reverse wrt transposed canonical state representation

	// global allocation
	// r8 - increment constant
	// r9 - AES_d4Td
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
	// r0 - s00T ^ s13T ^ s22T ^ s31T
	// r1 - s01T ^ s10T ^ s23T ^ s32T
	// r2 - s02T ^ s11T ^ s20T ^ s33T
	// r3 - s03T ^ s12T ^ s21T ^ s30T

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
	// r3 - AES_d4Td
	// r4 -  -  | s10 | s20 | s30
	// r5 -  -  | s11 | s21 | s31
	// r6 -  -  | s12 | s22 | s32
	// r7 - s03 | s13 | s23 | s33

	lsrs r3, r5, #24
	lsls r3, #4
	add r3, r9
	ldr r3, [r3, #12]

	eors r0, r3

	lsrs r3, r6, #24
	lsls r3, #4
	add r3, r9
	ldr r3, [r3, #12]

	eors r1, r3

	lsrs r3, r7, #24
	lsls r3, #4
	add r3, r9
	ldr r3, [r3, #12]

	eors r2, r3

	//current allocaton
	// r0 - s00T ^ s31T
	// r1 - s01T ^ s32T
	// r2 - s02T ^ s33T
	// r3 - AES_d4Td
	// r4 -  -  | s10 | s20 | s30
	// r5 -  -  | s11 | s21 |  -
	// r6 -  -  | s12 | s22 |  -
	// r7 - s03 | s13 | s23 |  -

	rev16 r5, r5
	rev16 r6, r6

	//current allocaton
	// r0 - s00T ^ s31T
	// r1 - s01T ^ s32T
	// r2 - s02T ^ s33T
	// r3 - AES_d4Td
	// r4 -  -  | s10 | s20 | s30
	// r5 - s11 |  -  |  -  | s21
	// r6 - s12 |  -  |  -  | s22
	// r7 - s03 | s13 | s23 |  -

	uxtb r3, r5
	lsls r3, #4
	add r3, r9
	ldr r3, [r3, #4]

	eors r2, r3

	lsrs r5, r5, #24
	lsls r5, #4
	add r5, r9
	ldr r5, [r5, #8]

	//current allocaton
	// r0 - s00T ^ s31T
	// r1 - s01T ^ s32T
	// r2 - s02T ^ s11T ^ s33T
	// r3 -
	// r4 -  -  | s10 | s20 | s30
	// r5 - s21T
	// r6 - s12 |  -  |  -  | s22
	// r7 - s03 | s13 | s23 |  -

	uxtb r3, r7
	lsls r3, #4
	add r3, r9
	ldr r3, [r3, #0]

	eors r3, r5

	lsrs r5, r4, #24
	lsls r5, #4
	add r5, r9
	ldr r5, [r5, #12]

	eors r3, r5

	//current allocaton
	// r0 - s00T ^ s31T
	// r1 - s01T ^ s32T
	// r2 - s02T ^ s11T ^ s33T
	// r3 - s03T ^ s21T ^ s30T
	// r4 -  -  | s10 | s20 |  -
	// r5 -
	// r6 - s12 |  -  |  -  | s22
	// r7 -  -  | s13 | s23 |  -

	uxtb r5, r6
	lsls r5, #4
	add r5, r9
	ldr r5, [r5, #4]

	eors r3, r5

	lsrs r6, r6, #24
	lsls r6, #4
	add r6, r9
	ldr r6, [r6, #8]

	eors r0, r6

	//current allocaton
	// r0 - s00T ^ s22T ^ s31T
	// r1 - s01T ^ s32T
	// r2 - s02T ^ s11T ^ s33T
	// r3 - s03T ^ s12T ^ s21T ^ s30T
	// r4 -  -  | s10 | s20 |  -
	// r5 -
	// r6 -
	// r7 -  -  | s13 | s23 |  -

	rev16 r4, r4

	uxtb r5, r4
	lsls r5, #4
	add r5, r9
	ldr r5, [r5, #4]

	eors r1, r5

	lsrs r4, r4, #24
	lsls r4, #4
	add r4, r9
	ldr r4, [r4, #8]

	eors r2, r4

	//current allocaton
	// r0 - s00T ^ s22T ^ s31T
	// r1 - s01T ^ s10T ^ s32T
	// r2 - s02T ^ s11T ^ s20T ^ s33T
	// r3 - s03T ^ s12T ^ s21T ^ s30T
	// r4 -
	// r5 -
	// r6 -
	// r7 -  -  | s13 | s23 |  -

	rev16 r7, r7

	uxtb r4, r7
	lsls r4, #4
	add r4, r9
	ldr r4, [r4, #4]

	eors r0, r4

	lsrs r7, r7, #24
	lsls r7, #4
	add r7, r9
	ldr r7, [r7, #8]

	eors r1, r7

	//current allocaton
	// r0 - s00T ^ s13T ^ s22T ^ s31T
	// r1 - s01T ^ s10T ^ s23T ^ s32T
	// r2 - s02T ^ s11T ^ s20T ^ s33T
	// r3 - s03T ^ s12T ^ s21T ^ s30T
	// r4 -
	// r5 -
	// r6 -
	// r7 -

	//addroundkey
	add r14, r8 // decrement rk
	mov r7, r14 // get rk

	ldm r7, {r4-r7}
	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	cmp r12, r14
	bne 1b

	//final round

	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 | s33

	//final
	// r0 - s00`| s13`| s22`| s31`
	// r1 - s01`| s10`| s23`| s32`
	// r2 - s02`| s11`| s20`| s33`
	// r3 - s03`| s12`| s21`| s30`

	ldr r3, =(AES_d4Td4 + 4) // can be anywhere within 16 bytes // use bank 2
	mov r9, r3

	uxtb r0, r4
	lsls r0, #4
	ldrb r0, [r3, r0]

	lsrs r1, r5, #24
	lsls r1, #4
	ldrb r1, [r3, r1]
	lsls r1, #24

	orrs r0, r1

	//current allocation
	// r0 - s00`|     |     | s31`
	// r1 -
	// r2 -
	// r3 - inv_sbox
	// r4 -  -  | s10 | s20 | s30
	// r5 - s01 | s11 | s21 |  -
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 | s33

	rev16 r2, r7

	uxtb r1, r2
	lsls r1, #4
	ldrb r1, [r3, r1]
	lsls r1, #8

	orrs r0, r1

	lsrs r2, r2, #24
	lsls r2, #4
	ldrb r2, [r3, r2]
	lsls r2, #16

	uxtb r1, r5
	lsls r1, #4
	ldrb r1, [r3, r1]

	orrs r1, r2

	//current allocation
	// r0 - s00`| s13`|     | s31`
	// r1 - s01`|     | s23`|
	// r2 -
	// r3 - inv_sbox
	// r4 -  -  | s10 | s20 | s30
	// r5 -  -  | s11 | s21 |  -
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 |  -  |  -  | s33

	lsrs r2, r6, #24
	lsls r2, #4
	ldrb r2, [r3, r2]
	lsls r2, #24

	orrs r1, r2

	lsrs r2, r7, #24
	lsls r2, #4
	ldrb r2, [r3, r2]
	lsls r2, #24

	//current allocation
	// r0 - s00`| s13`|     | s31`
	// r1 - s01`|     | s23`| s32`
	// r2 -     |     |     | s33`
	// r3 - inv_sbox
	// r4 -  -  | s10 | s20 | s30
	// r5 -  -  | s11 | s21 |  -
	// r6 - s02 | s12 | s22 |  -
	// r7 - s03 |  -  |  -  |  -

	uxtb r7, r7
	lsls r7, #4
	ldrb r7, [r3, r7]

	rev16 r5, r5

	lsrs r3, r5, #24 // too high pressure
	lsls r3, #4
	add r3, r9 // pointer spilled
	ldrb r3, [r3]
	lsls r3, #16

	orrs r3, r7

	//current allocation
	// r0 - s00`| s13`|     | s31`
	// r1 - s01`|     | s23`| s32`
	// r2 -     |     |     | s33`
	// r3 - s03`|     | s21`|
	// r4 -  -  | s10 | s20 | s30
	// r5 - s11 |  -  |  -  |  -
	// r6 - s02 | s12 | s22 |  -
	// r7 - inv_sbox

	mov r7, r9 // get inv_sbox back

	uxtb r5, r5
	lsls r5, #4
	ldrb r5, [r7, r5]
	lsls r5, #8

	orrs r2, r5

	//current allocation
	// r0 - s00`| s13`|     | s31`
	// r1 - s01`|     | s23`| s32`
	// r2 -     | s11`|     | s33`
	// r3 - s03`|     | s21`|
	// r4 -  -  | s10 | s20 | s30
	// r5 -
	// r6 - s02 | s12 | s22 |  -
	// r7 - inv_sbox

	uxtb r5, r6
	lsls r5, #4
	ldrb r5, [r7, r5]

	orrs r2, r5

	lsrs r5, r4, #24
	lsls r5, #4
	ldrb r5, [r7, r5]
	lsls r5, #24

	orrs r3, r5

	//current allocation
	// r0 - s00`| s13`|     | s31`
	// r1 - s01`|     | s23`| s32`
	// r2 - s02`| s11`|     | s33`
	// r3 - s03`|     | s21`| s30`
	// r4 -  -  | s10 | s20 |  -
	// r5 -
	// r6 -  -  | s12 | s22 |  -
	// r7 - inv_sbox

	rev16 r4, r4

	uxtb r5, r4
	lsls r5, #4
	ldrb r5, [r7, r5]
	lsls r5, #8

	orrs r1, r5

	lsrs r4, r4, #24
	lsls r4, #4
	ldrb r4, [r7, r4]
	lsls r4, #16

	orrs r2, r4

	//current allocation
	// r0 - s00`| s13`|     | s31`
	// r1 - s01`| s10`| s23`| s32`
	// r2 - s02`| s11`| s20`| s33`
	// r3 - s03`|     | s21`| s30`
	// r4 -
	// r5 -
	// r6 -  -  | s12 | s22 |  -
	// r7 - inv_sbox

	rev16 r6, r6

	uxtb r5, r6
	lsls r5, #4
	ldrb r5, [r7, r5]
	lsls r5, #8

	orrs r3, r5

	lsrs r6, r6, #24
	lsls r6, #4
	ldrb r6, [r7, r6]
	lsls r6, #16

	orrs r0, r6

	//current allocation
	// r0 - s00`| s13`| s22`| s31`
	// r1 - s01`| s10`| s23`| s32`
	// r2 - s02`| s11`| s20`| s33`
	// r3 - s03`| s12`| s21`| s30`
	// r4 -
	// r5 -
	// r6 -
	// r7 - inv_sbox

	//final addroundkey
	add r14, r8 // decrement rk
	mov r7, r14 // get rk

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
