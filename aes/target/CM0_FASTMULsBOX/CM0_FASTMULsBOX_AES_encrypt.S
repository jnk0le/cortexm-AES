/*!
 * \file CM0_FASTMULsBOX_AES_encrypt.S
 * \brief cortex-m0 optimized aes encryption
 *
 * utilizes basic sbox table
 * requires single cycle multiplier, otherwise it's slower than standard version
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
// void CM0_FASTMULsBOX_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM0_FASTMULsBOX_AES_encrypt
.type   CM0_FASTMULsBOX_AES_encrypt,%function
CM0_FASTMULsBOX_AES_encrypt:
	push {r2, r4-r7, lr} // stack out ptr (faster than pressure on upper regs)
	mov r4, r8
	mov r5, r9
	mov r6, r10
	push {r4-r6}

	//rk incrementer
	movs r4, #16
	mov r8, r4

	ldr r5, =AES_sbox
	mov r9, r5 // AES_sbox

	ldr r6, =0x01010101
	mov r10, r6 // 0x01010101

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

	// state elements will be represented with big endian order (transposed canonical state representation)
	// columns are loaded in little endian so right/left in shifts is in reverse wrt transposed canonical state representation

	// global allocation
	// r8 - increment constant
	// r9 - sbox
	// r10 - 0x01010101
	// r11 - x
	// r12 - final ptr
	// r14 - current ptr

	mov r3, r9 // get sbox here to align loop entry, next getter is at the end of loop

1:	//shiftrows and subbytes

	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 | s33

	//final
	// r0 - s00`| s11`| s22`| s33`
	// r1 - s01`| s12`| s23`| s30`
	// r2 - s02`| s13`| s20`| s31`
	// r3 - s03`| s10`| s21`| s32`

	uxtb r0, r4
	ldrb r0, [r3, r0]

	lsrs r1, r7, #24
	ldrb r1, [r3, r1]
	lsls r1, #24

	orrs r0, r1

	//current allocation
	// r0 - s00`|     |     | s33`
	// r1 -
	// r2 -
	// r3 - sbox
	// r4 -  -  | s10 | s20 | s30
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 |  -

	rev16 r2, r6

	lsrs r1, r2, #24
	ldrb r1, [r3, r1]
	lsls r1, #16

	orrs r0, r1

	uxtb r2, r2
	ldrb r2, [r3, r2]
	lsls r2, #8

	uxtb r1, r5
	ldrb r1, [r3, r1]

	orrs r1, r2

	//current allocation
	// r0 - s00`|     | s22`| s33`
	// r1 - s01`| s12`|     |
	// r2 -
	// r3 - sbox
	// r4 -  -  | s10 | s20 | s30
	// r5 -  -  | s11 | s21 | s31
	// r6 - s02 |  -  |  -  | s32
	// r7 - s03 | s13 | s23 |  -

	lsrs r2, r4, #24
	ldrb r2, [r3, r2]
	lsls r2, #24

	orrs r1, r2

	uxtb r2, r6
	ldrb r2, [r3, r2]

	//current allocation
	// r0 - s00`|     | s22`| s33`
	// r1 - s01`| s12`|     | s30`
	// r2 - s02`|     |     |
	// r3 - sbox
	// r4 -  -  | s10 | s20 |  -
	// r5 -  -  | s11 | s21 | s31
	// r6 -  -  |  -  |  -  | s32
	// r7 - s03 | s13 | s23 |  -

	lsrs r6, #24
	ldrb r6, [r3, r6]
	lsls r6, #24

	rev16 r4, r4

	uxtb r3, r4 // too high pressure
	add r3, r9 // pointer spilled
	ldrb r3, [r3]
	lsls r3, #8

	orrs r3, r6

	//current allocation
	// r0 - s00`|     | s22`| s33`
	// r1 - s01`| s12`|     | s30`
	// r2 - s02`|     |     |
	// r3 -     | s10`|     | s32`
	// r4 -  -  |  -  |  -  | s20
	// r5 -  -  | s11 | s21 | s31
	// r6 -
	// r7 - s03 | s13 | s23 |  -

	mov r6, r9 // get sbox back

	lsrs r4, #24
	ldrb r4, [r6, r4]
	lsls r4, #16

	orrs r2, r4

	//current allocation
	// r0 - s00`|     | s22`| s33`
	// r1 - s01`| s12`|     | s30`
	// r2 - s02`|     | s20`|
	// r3 -     | s10`|     | s32`
	// r4 -
	// r5 -  -  | s11 | s21 | s31
	// r6 - sbox
	// r7 - s03 | s13 | s23 |  -

	uxtb r4, r7
	ldrb r4, [r6, r4]

	orrs r3, r4

	lsrs r4, r5, #24
	ldrb r4, [r6, r4]
	lsls r4, #24

	orrs r2, r4

	//current allocation
	// r0 - s00`|     | s22`| s33`
	// r1 - s01`| s12`|     | s30`
	// r2 - s02`|     | s20`| s31`
	// r3 - s03`| s10`|     | s32`
	// r4 -
	// r5 -  -  | s11 | s21 |  -
	// r6 - sbox
	// r7 -  -  | s13 | s23 |  -

	rev16 r5, r5

	uxtb r4, r5
	ldrb r4, [r6, r4]
	lsls r4, #8

	orrs r0, r4

	lsrs r5, #24
	ldrb r5, [r6, r5]
	lsls r5, #16

	orrs r3, r5

	//current allocation
	// r0 - s00`| s11`| s22`| s33`
	// r1 - s01`| s12`|     | s30`
	// r2 - s02`|     | s20`| s31`
	// r3 - s03`| s10`| s21`| s32`
	// r4 -
	// r5 -
	// r6 - sbox
	// r7 -  -  | s13 | s23 |  -

	rev16 r7, r7

	uxtb r4, r7
	ldrb r4, [r6, r4]
	lsls r4, #8

	orrs r2, r4

	lsrs r7, #24
	ldrb r7, [r6, r7]
	lsls r7, #16

	orrs r1, r7

	//current allocation
	// r0 - s00`| s11`| s22`| s33`
	// r1 - s01`| s12`| s23`| s30`
	// r2 - s02`| s13`| s20`| s31`
	// r3 - s03`| s10`| s21`| s32`

	// do mix columns as
	// tmp = s0 ^ s1 ^ s2 ^ s3
	// s0` ^= tmp ^ gmul2(s0^s1) // s1^s2^s3^gmul2(s0^s1)
	// s1` ^= tmp ^ gmul2(s1^s2) // s0^s2^s3^gmul2(s1^s2)
	// s2` ^= tmp ^ gmul2(s2^s3) // s0^s1^s3^gmul2(s2^s3)
	// S3` ^= tmp ^ gmul2(s3^s0) // s0^s1^s2^gmul2(s3^s0)

	// use approach with 1 more xor instead of rotation

	mov r4, r10 // 0x01010101
	movs r5, #0x1b

	// 2 registers + 1 in/out are free // column 0 comes in r3 insteadof r4, need to correct it's position before mul

	//col 0
	lsrs r6, r0, #8 // need to preserve input, so rors makes no diff
	lsls r7, r0, #24
	orrs r6, r7

	eors r6, r0 // s0^s1 | s1^s2 | s2^s3 | s3^s0

	rev16 r7, r6 // ror #16
	rev r7, r7 // ror #16

	eors r7, r6 // s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	eors r0, r7 // s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	/*now mult r2 and eors it into r4 // r3 free

	do quad multiplication according to:
	// out = ((in & 0x7f7f7f7f) << 1) ^ (((in & 0x80808080) >> 7)) * 0x1b);

	modified to perform shifts first to avoid one extra mov
	// out = ((in << 1) & 0xfefefefe) ^ (((in >> 7) & 0x01010101) * 0x1b)
	*/

	lsrs r7, r6, #7
	ands r7, r4 // mask
	muls r7, r5 // get predicated reduction

	lsls r6, #1
	bics r6, r4 // & 0xfe // can also eors with r7

	eors r6, r7 // reduce
	eors r0, r6 // final

	//col 1
	lsrs r6, r1, #8 // need to preserve input, so rors makes no diff
	lsls r7, r1, #24
	orrs r6, r7

	eors r6, r1 // s0^s1 | s1^s2 | s2^s3 | s3^s0

	rev16 r7, r6 // ror #16
	rev r7, r7 // ror #16

	eors r7, r6 // s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	eors r1, r7 // s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	lsrs r7, r6, #7
	ands r7, r4 // mask
	muls r7, r5 // get predicated reduction

	lsls r6, #1
	bics r6, r4 // & 0xfe // can also eors with r7

	eors r6, r7 // reduce
	eors r1, r6 // final

	//col 2
	lsrs r6, r2, #8 // need to preserve input, so rors makes no diff
	lsls r7, r2, #24
	orrs r6, r7

	eors r6, r2 // s0^s1 | s1^s2 | s2^s3 | s3^s0

	rev16 r7, r6 // ror #16
	rev r7, r7 // ror #16

	eors r7, r6 // s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	eors r2, r7 // s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	lsrs r7, r6, #7
	ands r7, r4 // mask
	muls r7, r5 // get predicated reduction

	lsls r6, #1
	bics r6, r4 // & 0xfe // can also eors with r7

	eors r6, r7 // reduce
	eors r2, r6 // final

	//col 3
	lsrs r6, r3, #8 // need to preserve input, so rors makes no diff
	lsls r7, r3, #24
	orrs r6, r7

	eors r6, r3 // s0^s1 | s1^s2 | s2^s3 | s3^s0

	rev16 r7, r6 // ror #16
	rev r7, r7 // ror #16

	eors r7, r6 // s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	eors r3, r7 // s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	lsrs r7, r6, #7
	ands r7, r4 // mask
	muls r7, r5 // get predicated reduction

	lsls r6, #1
	bics r6, r4 // & 0xfe // can also eors with r7

	eors r6, r7 // reduce
	eors r3, r6 // final

	//addroundkey
	mov r7, r14 // get current rk
	add r14, r8 // increment rk by 16

	ldm r7, {r4-r7}
	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	mov r3, r9 // get sbox for next round or final round

	cmp r14, r12
	beq 2f // if rk reached final condition
	b 1b // out of range for conditional branch

2:	//final round

	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 | s33

	//final
	// r0 - s00`| s11`| s22`| s33`
	// r1 - s01`| s12`| s23`| s30`
	// r2 - s02`| s13`| s20`| s31`
	// r3 - s03`| s10`| s21`| s32`

	uxtb r0, r4
	ldrb r0, [r3, r0]

	lsrs r1, r7, #24
	ldrb r1, [r3, r1]
	lsls r1, #24

	orrs r0, r1

	//current allocation
	// r0 - s00`|     |     | s33`
	// r1 -
	// r2 -
	// r3 - sbox
	// r4 -  -  | s10 | s20 | s30
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 |  -

	rev16 r2, r6

	lsrs r1, r2, #24
	ldrb r1, [r3, r1]
	lsls r1, #16

	orrs r0, r1

	uxtb r2, r2
	ldrb r2, [r3, r2]
	lsls r2, #8

	uxtb r1, r5
	ldrb r1, [r3, r1]

	orrs r1, r2

	//current allocation
	// r0 - s00`|     | s22`| s33`
	// r1 - s01`| s12`|     |
	// r2 -
	// r3 - sbox
	// r4 -  -  | s10 | s20 | s30
	// r5 -  -  | s11 | s21 | s31
	// r6 - s02 |  -  |  -  | s32
	// r7 - s03 | s13 | s23 |  -

	lsrs r2, r4, #24
	ldrb r2, [r3, r2]
	lsls r2, #24

	orrs r1, r2

	uxtb r2, r6
	ldrb r2, [r3, r2]

	//current allocation
	// r0 - s00`|     | s22`| s33`
	// r1 - s01`| s12`|     | s30`
	// r2 - s02`|     |     |
	// r3 - sbox
	// r4 -  -  | s10 | s20 |  -
	// r5 -  -  | s11 | s21 | s31
	// r6 -  -  |  -  |  -  | s32
	// r7 - s03 | s13 | s23 |  -

	lsrs r6, #24
	ldrb r6, [r3, r6]
	lsls r6, #24

	rev16 r4, r4

	uxtb r3, r4 // too high pressure
	add r3, r9 // pointer spilled
	ldrb r3, [r3]
	lsls r3, #8

	orrs r3, r6

	//current allocation
	// r0 - s00`|     | s22`| s33`
	// r1 - s01`| s12`|     | s30`
	// r2 - s02`|     |     |
	// r3 -     | s10`|     | s32`
	// r4 -  -  |  -  |  -  | s20
	// r5 -  -  | s11 | s21 | s31
	// r6 -
	// r7 - s03 | s13 | s23 |  -

	mov r6, r9 // get sbox back

	lsrs r4, #24
	ldrb r4, [r6, r4]
	lsls r4, #16

	orrs r2, r4

	//current allocation
	// r0 - s00`|     | s22`| s33`
	// r1 - s01`| s12`|     | s30`
	// r2 - s02`|     | s20`|
	// r3 -     | s10`|     | s32`
	// r4 -
	// r5 -  -  | s11 | s21 | s31
	// r6 - sbox
	// r7 - s03 | s13 | s23 |  -

	uxtb r4, r7
	ldrb r4, [r6, r4]

	orrs r3, r4

	lsrs r4, r5, #24
	ldrb r4, [r6, r4]
	lsls r4, #24

	orrs r2, r4

	//current allocation
	// r0 - s00`|     | s22`| s33`
	// r1 - s01`| s12`|     | s30`
	// r2 - s02`|     | s20`| s31`
	// r3 - s03`| s10`|     | s32`
	// r4 -
	// r5 -  -  | s11 | s21 |  -
	// r6 - sbox
	// r7 -  -  | s13 | s23 |  -

	rev16 r5, r5

	uxtb r4, r5
	ldrb r4, [r6, r4]
	lsls r4, #8

	orrs r0, r4

	lsrs r5, #24
	ldrb r5, [r6, r5]
	lsls r5, #16

	orrs r3, r5

	//current allocation
	// r0 - s00`| s11`| s22`| s33`
	// r1 - s01`| s12`|     | s30`
	// r2 - s02`|     | s20`| s31`
	// r3 - s03`| s10`| s21`| s32`
	// r4 -
	// r5 -
	// r6 - sbox
	// r7 -  -  | s13 | s23 |  -

	rev16 r7, r7

	uxtb r4, r7
	ldrb r4, [r6, r4]
	lsls r4, #8

	orrs r2, r4

	lsrs r7, #24
	ldrb r7, [r6, r7]
	lsls r7, #16

	orrs r1, r7

	//current allocation
	// r0 - s00`| s11`| s22`| s33`
	// r1 - s01`| s12`| s23`| s30`
	// r2 - s02`| s13`| s20`| s31`
	// r3 - s03`| s10`| s21`| s32`

	//final addroundkey
	mov r7, r14 // get current rk

	ldm r7, {r4-r7}
	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	pop {r0-r2, r3} // pop to non data // unstack also out pointer
	mov r8, r0
	mov r9, r1
	mov r10, r2

	stmia r3!, {r4-r7}

	pop {r4-r7, pc}

#endif
