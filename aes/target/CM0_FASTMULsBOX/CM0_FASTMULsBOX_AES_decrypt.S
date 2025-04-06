/*!
 * \file CM0_FASTMULsBOX_AES_decrypt.S
 * \brief cortex-m0 optimized aes decryption
 *
 * utilizes basic inv_sbox table
 * requires single cycle multiplier, otherwise it's slower than standard version
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
// void CM0_FASTMULsBOX_AES_decrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM0_FASTMULsBOX_AES_decrypt
.type   CM0_FASTMULsBOX_AES_decrypt,%function
CM0_FASTMULsBOX_AES_decrypt:
	push {r2, r4-r7, lr} // stack out ptr (faster than pressure on upper regs)
	mov r4, r8
	mov r5, r9
	mov r6, r10
	mov r7, r11
	push {r4-r7}

	adr r2, aes_dec_constants
	ldmia r2!, {r5,r6,r7}
	mov r9, r5 // AES_inv_sbox
	mov r10, r6 // 0x01010101
	mov r11, r7 // 0x80808080

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

	// initial addroundkey
	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	// r8 - decrement constant
	// r9 - inv_sbox
	// r10 - 0x01010101
	// r11 - 0x80808080
	// r12 - final ptr // rk+16
	// r14 - current ptr

	mov r3, r9 // get inv_sbox here to align loop entry, next getter is at the end of loop

1:	//inv shiftrows and invsubbytes

	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 | s33

	//final
	// r0 - s00`| s13`| s22`| s31`
	// r1 - s01`| s10`| s23`| s32`
	// r2 - s02`| s11`| s20`| s33`
	// r3 - s03`| s12`| s21`| s30`

	uxtb r0, r4
	ldrb r0, [r3, r0]

	lsrs r1, r5, #24
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
	ldrb r1, [r3, r1]
	lsls r1, #8

	orrs r0, r1

	lsrs r2, r2, #24
	ldrb r2, [r3, r2]
	lsls r2, #16

	uxtb r1, r5
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
	ldrb r2, [r3, r2]
	lsls r2, #24

	orrs r1, r2

	lsrs r2, r7, #24
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
	ldrb r7, [r3, r7]

	rev16 r5, r5

	lsrs r3, r5, #24 // too high pressure
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
	ldrb r5, [r7, r5]

	orrs r2, r5

	lsrs r5, r4, #24
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
	ldrb r5, [r7, r5]
	lsls r5, #8

	orrs r1, r5

	lsrs r4, r4, #24
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
	ldrb r5, [r7, r5]
	lsls r5, #8

	orrs r3, r5

	lsrs r6, r6, #24
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

	//addroundkey
	add r14, r8 // decrement rk
	mov r7, r14 // get rk

	ldm r7, {r4-r7}
	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	//invmixcolums
	//constants have to be vented on during column

	//col 0
	mov r0, r10 // 0x01010101
	movs r1, 0x1b

	//expand S{1} to S{2}, S{4}, S{8}
	//all of them have to be preserved

	/* do quad multiplication according to:
	// out = ((in & 0x7f7f7f7f) << 1) ^ (((in & 0x80808080) >> 7)) * 0x1b);

	some calculations are modified to perform shifts first to avoid extra moves
	// out = ((in << 1) & 0xfefefefe) ^ (((in >> 7) & 0x01010101) * 0x1b)
	*/

	lsrs r3, r4, #7
	ands r3, r0 // mask
	muls r3, r1 // get predicated reduction

	lsls r2, r4, #1
	bics r2, r0 // & 0xfe

	eors r2, r3 // S{2}

	lsls r3, r2, #1
	bics r3, r0

	mov r0, r11 // lsls r0, #7 // need 0x80808080 anyway

	ands r0, r2 // mask
	lsrs r0, #7
	muls r0, r1 // get predicated reduction

	eors r3, r0 // S{4}

	// need 0x80808080 due to register presure
	mov r0, r11 // get 0x80808080

	ands r0, r3 // mask

	lsrs r0, #7
	muls r1, r0 // get predicated reduction

	lsls r0, #7 // get mask bits into high pos

	eors r0, r3 // equivalent to &0x7f
	lsls r0, #1
	eors r1, r0 // S{8}

	// r0 -
	// r1 -	S{8}
	// r2 - S{2}
	// r3 - S{4}
	// r4 - S{1}

	eors r4, r1 // S{9}
	eors r1, r2
	eors r1, r3 // S{e}
	eors r2, r4 // S{b}
	eors r3, r4 // S{d}

	// S{9} - ror #24
	// S{b} - ror #8
	// S{d} - ror #16
	// S{e} - ror #0

	movs r0, #24
	rors r4, r0

	eors r4, r1 // s0{e}^s3{9} | s1{e}^s0{9} | s2{e}^s1{9} | s3{e}^s2{9}

	movs r0, #8
	rors r2, r0

	eors r4, r2 // s0{e}^s1{b}^s3{9} | s1{e}^s2{b}^s0{9} | s2{e}^s3{b}^s1{9} | s3{e}^s0{b}^s2{9}

	rev16 r3, r3
	rev r3, r3

	eors r4, r3// s0{e}^s1{b}^s2{d}^s3{9} | s1{e}^s2{b}^s3{d}^s0{9} | s2{e}^s3{b}^s0{d}^s1{9} | s3{e}^s0{b}^s1{d}^s2{9}

	//col 1
	mov r0, r10 // 0x01010101
	movs r1, 0x1b

	lsrs r3, r5, #7
	ands r3, r0 // mask
	muls r3, r1 // get predicated reduction

	lsls r2, r5, #1
	bics r2, r0 // & 0xfe

	eors r2, r3 // S{2}

	lsls r3, r2, #1
	bics r3, r0

	mov r0, r11 // lsls r0, #7 // need 0x80808080 anyway

	ands r0, r2 // mask
	lsrs r0, #7
	muls r0, r1 // get predicated reduction

	eors r3, r0 // S{4}

	// need 0x80808080 due to register presure
	mov r0, r11 // get 0x80808080

	ands r0, r3 // mask

	lsrs r0, #7
	muls r1, r0 // get predicated reduction

	lsls r0, #7 // get mask bits into high pos

	eors r0, r3 // equivalent to &0x7f
	lsls r0, #1
	eors r1, r0 // S{8}

	eors r5, r1 // S{9}
	eors r1, r2
	eors r1, r3 // S{e}
	eors r2, r5 // S{b}
	eors r3, r5 // S{d}

	movs r0, #24
	rors r5, r0

	eors r5, r1 // s0{e}^s3{9} | s1{e}^s0{9} | s2{e}^s1{9} | s3{e}^s2{9}

	movs r0, #8
	rors r2, r0

	eors r5, r2 // s0{e}^s1{b}^s3{9} | s1{e}^s2{b}^s0{9} | s2{e}^s3{b}^s1{9} | s3{e}^s0{b}^s2{9}

	rev16 r3, r3
	rev r3, r3

	eors r5, r3 // s0{e}^s1{b}^s2{d}^s3{9} | s1{e}^s2{b}^s3{d}^s0{9} | s2{e}^s3{b}^s0{d}^s1{9} | s3{e}^s0{b}^s1{d}^s2{9}

	//col 2
	mov r0, r10 // 0x01010101
	movs r1, 0x1b

	lsrs r3, r6, #7
	ands r3, r0 // mask
	muls r3, r1 // get predicated reduction

	lsls r2, r6, #1
	bics r2, r0 // & 0xfe

	eors r2, r3 // S{2}

	lsls r3, r2, #1
	bics r3, r0

	mov r0, r11 // lsls r0, #7 // need 0x80808080 anyway

	ands r0, r2 // mask
	lsrs r0, #7
	muls r0, r1 // get predicated reduction

	eors r3, r0 // S{4}

	// need 0x80808080 due to register presure
	mov r0, r11 // get 0x80808080

	ands r0, r3 // mask

	lsrs r0, #7
	muls r1, r0 // get predicated reduction

	lsls r0, #7 // get mask bits into high pos

	eors r0, r3 // equivalent to &0x7f
	lsls r0, #1
	eors r1, r0 // S{8}

	eors r6, r1 // S{9}
	eors r1, r2
	eors r1, r3 // S{e}
	eors r2, r6 // S{b}
	eors r3, r6 // S{d}

	movs r0, #24
	rors r6, r0

	eors r6, r1 // s0{e}^s3{9} | s1{e}^s0{9} | s2{e}^s1{9} | s3{e}^s2{9}

	movs r0, #8
	rors r2, r0

	eors r6, r2 // s0{e}^s1{b}^s3{9} | s1{e}^s2{b}^s0{9} | s2{e}^s3{b}^s1{9} | s3{e}^s0{b}^s2{9}

	rev16 r3, r3
	rev r3, r3

	eors r6, r3// s0{e}^s1{b}^s2{d}^s3{9} | s1{e}^s2{b}^s3{d}^s0{9} | s2{e}^s3{b}^s0{d}^s1{9} | s3{e}^s0{b}^s1{d}^s2{9}

	//col 3
	mov r0, r10 // 0x01010101
	movs r1, 0x1b

	lsrs r3, r7, #7
	ands r3, r0 // mask
	muls r3, r1 // get predicated reduction

	lsls r2, r7, #1
	bics r2, r0 // & 0xfe

	eors r2, r3 // S{2}

	lsls r3, r2, #1
	bics r3, r0

	mov r0, r11 // lsls r0, #7 // need 0x80808080 anyway

	ands r0, r2 // mask
	lsrs r0, #7
	muls r0, r1 // get predicated reduction

	eors r3, r0 // S{4}

	// need 0x80808080 due to register presure
	mov r0, r11 // get 0x80808080

	ands r0, r3 // mask

	lsrs r0, #7
	muls r1, r0 // get predicated reduction

	lsls r0, #7 // get mask bits into high pos

	eors r0, r3 // equivalent to &0x7f
	lsls r0, #1
	eors r1, r0 // S{8}

	eors r7, r1 // S{9}
	eors r1, r2
	eors r1, r3 // S{e}
	eors r2, r7 // S{b}
	eors r3, r7 // S{d}

	movs r0, #24
	rors r7, r0

	eors r7, r1 // s0{e}^s3{9} | s1{e}^s0{9} | s2{e}^s1{9} | s3{e}^s2{9}

	movs r0, #8
	rors r2, r0

	eors r7, r2 // s0{e}^s1{b}^s3{9} | s1{e}^s2{b}^s0{9} | s2{e}^s3{b}^s1{9} | s3{e}^s0{b}^s2{9}

	rev16 r3, r3
	rev r3, r3

	eors r7, r3// s0{e}^s1{b}^s2{d}^s3{9} | s1{e}^s2{b}^s3{d}^s0{9} | s2{e}^s3{b}^s0{d}^s1{9} | s3{e}^s0{b}^s1{d}^s2{9}

	mov r3, r9 // get inv_sbox for next round or final round

	cmp r14, r12
	beq 2f // if rk reached final condition
	b 1b // out of range for conditional branch

2:	//final round

	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 | s33

	//final
	// r0 - s00`| s13`| s22`| s31`
	// r1 - s01`| s10`| s23`| s32`
	// r2 - s02`| s11`| s20`| s33`
	// r3 - s03`| s12`| s21`| s30`

	uxtb r0, r4
	ldrb r0, [r3, r0]

	lsrs r1, r5, #24
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
	ldrb r1, [r3, r1]
	lsls r1, #8

	orrs r0, r1

	lsrs r2, r2, #24
	ldrb r2, [r3, r2]
	lsls r2, #16

	uxtb r1, r5
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
	ldrb r2, [r3, r2]
	lsls r2, #24

	orrs r1, r2

	lsrs r2, r7, #24
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
	ldrb r7, [r3, r7]

	rev16 r5, r5

	lsrs r3, r5, #24 // too high pressure
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
	ldrb r5, [r7, r5]

	orrs r2, r5

	lsrs r5, r4, #24
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
	ldrb r5, [r7, r5]
	lsls r5, #8

	orrs r1, r5

	lsrs r4, r4, #24
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
	ldrb r5, [r7, r5]
	lsls r5, #8

	orrs r3, r5

	lsrs r6, r6, #24
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

	//can't pop all at once
	pop {r0-r1}
	mov r8, r0
	mov r9, r1

	pop {r0-r1, r3} // pop to non data // unstack also out pointer
	mov r10, r0
	mov r11, r1

	stmia r3!, {r4-r7}

	pop {r4-r7, pc}

.balign 4
aes_dec_constants:
	.long AES_inv_sbox
	.long 0x01010101
	.long 0x80808080

#endif
