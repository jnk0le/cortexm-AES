/*!
 * \file CM0_FASTMULsBOX_AES_decrypt.S
 * \brief
 *
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date 10 nov 2021
 */

//key goes backward

.syntax unified
.thumb
.text

.align 2
// void CM0_FASTMULsBOX_AES_decrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM0_FASTMULsBOX_AES_decrypt
.type   CM0_FASTMULsBOX_AES_decrypt,%function
CM0_FASTMULsBOX_AES_decrypt:
	push {r2, r4-r7, lr} // stack out ptr (faster than pressure on upper regs)
	mov r4, r8
	mov r5, r9
	mov r6, r10
	push {r4-r6}

	ldr r5, =AES_inv_sbox
	mov r9, r5 // AES_sbox

	ldr r6, =0x80808080
	mov r10, r6 // 0x80808080

	movs r2, #16

	negs r4, r2 // hireg add will now subtract
	mov r8, r4 // rk decrementer

	adds r2, r0 // rk+16
	mov r12, r2 // final rk

	//create end rk+0 + rounds * 16
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
	// r10 - 0x80808080
	// r12 - final ptr // rk+16
	// r14 - current ptr

	mov r0, r9 // get inv_sbox here to align loop entry, next getter is at the end of loop

1:	//inv shiftrows and invsubbytes

	//saved 2 cycles on rev16 // lost 2 cycles on inv_sbox pressured out, 1 on extra mov

	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 | s33

	//final
	// r4 - s00`| s13`| s22`| s31`
	// r5 - s01`| s10`| s23`| s32`
	// r6 - s02`| s11`| s20`| s33`
	// r7 - s03`| s12`| s21`| s30`

	lsrs r1, r4, #24
	ldrb r1, [r0, r1]
	lsls r1, #24

	rev16 r3, r7

	// r0 - inv_sbox
	// r1 -     |     |     | s30`
	// r2 -
	// r3 - s13 |  -  |  -  | s23

	// r4 - s00 | s10 | s20 |  -
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 |  -  |  -  | s33

	lsrs r2, r7, #24
	ldrb r2, [r0, r2]
	lsls r2, #24

	uxtb r7, r7
	ldrb r7, [r0, r7]

	orrs r7, r1

	// r0 - inv_sbox
	// r1 -
	// r2 -     |     |     | s33`
	// r3 - s13 |  -  |  -  | s23

	// r4 - s00 | s10 | s20 |  -
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03`|  -  |  -  | s30`

	lsrs r1, r6, #8
	uxtb r1, r1
	ldrb r1, [r0, r1]
	lsls r1, #8

	orrs r7, r1

	lsrs r1, r5, #16
	uxtb r1, r1
	ldrb r1, [r0, r1]
	lsls r1, #16

	orrs r7, r1

	// r0 - inv_sbox
	// r1 -
	// r2 -     |     |     | s33`
	// r3 - s13 |  -  |  -  | s23

	// r4 - s00 | s10 | s20 |  -
	// r5 - s01 | s11 |  -  | s31
	// r6 - s02 |  -  | s22 | s32
	// r7 - s03`| s12`| s21`| s30`

	lsrs r1, r5, #8
	uxtb r1, r1
	ldrb r1, [r0, r1]
	lsls r1, #8

	orrs r2, r1

	// r0 - inv_sbox
	// r1 -
	// r2 -     | s11`|     | s33`
	// r3 - s13 |  -  |  -  | s23

	// r4 - s00 | s10 | s20 |  -
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02 |  -  | s22 | s32
	// r7 - s03`| s12`| s21`| s30`

	//ror16 from r4 ?

	mov r1, r6 // free up s02

	uxtb r6, r6
	ldrb r6, [r0, r6]

	orrs r6, r2

	// r0 - inv_sbox
	// r1 -  -  |  -  | s22 | s32
	// r2 -
	// r3 - s13 |  -  |  -  | s23

	// r4 - s00 | s10 | s20 |  -
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02`| s11`|  -  | s33`
	// r7 - s03`| s12`| s21`| s30`

	lsrs r2, r3, #24
	ldrb r2, [r0, r2]
	lsls r2, #16

	uxtb r3, r3
	ldrb r3, [r0, r3]
	lsls r3, #8

	// r0 - inv_sbox
	// r1 -  -  |  -  | s22 | s32
	// r2 -     |     | s23`|
	// r3 -     | s13`|     |

	// r4 - s00 | s10 | s20 |  -
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02`| s11`|  -  | s33`
	// r7 - s03`| s12`| s21`| s30`

	lsrs r0, r1, #24 // too high pressure
	add r0, r9 // add inv_sbox base
	ldrb r0, [r0]
	lsls r0, #24

	orrs r2, r0

	mov r0, r9 // get inv_sbox back

	// r0 - inv_sbox
	// r1 -  -  |  -  | s22 |  -
	// r2 -     |     | s23`| s32`
	// r3 -     | s13`|     |

	// r4 - s00 | s10 | s20 |  -
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02`| s11`|  -  | s33`
	// r7 - s03`| s12`| s21`| s30`

	lsrs r1, #16
	uxtb r1, r1
	ldrb r1, [r0, r1]
	lsls r1, #16

	orrs r3, r1

	// r0 - inv_sbox
	// r1 -
	// r2 -     |     | s23`| s32`
	// r3 -     | s13`| s22`|

	// r4 - s00 | s10 | s20 |  -
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02`| s11`|  -  | s33`
	// r7 - s03`| s12`| s21`| s30`

	rev16 r1, r4

	uxtb r4, r4
	ldrb r4, [r0, r4]

	orrs r4, r3

	lsrs r3, r5, #24
	ldrb r3, [r0, r3]
	lsls r3, #24

	orrs r4, r3

	// r0 - inv_sbox
	// r1 - s10 |     |     | s20
	// r2 -     |     | s23`| s32`
	// r3 -

	// r4 - s00`| s13`| s22`| s31`
	// r5 - s01 |  -  |  -  |  -
	// r6 - s02`| s11`|  -  | s33`
	// r7 - s03`| s12`| s21`| s30`

	uxtb r5, r5
	ldrb r5, [r0, r5]

	orrs r5, r2

	lsrs r3, r1, #24
	ldrb r3, [r0, r3]
	lsls r3, #16

	orrs r6, r3

	uxtb r1, r1
	ldrb r1, [r0, r1]
	lsls r1, #8

	orrs r5, r1

	//addroundkey
	add r14, r8 // decrement rk
	mov r0, r14 // get rk

	ldm r0, {r0-r3}
	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	//invmixcolums
	//constants have to be vented on each column

	//col 0
	mov r0, r10 // 0x80808080
	movs r1, 0x1b

	//expand S{1} to S{2}, S{4}, S{8}

	/* do quad multiplication according to:
	// mask = in & 0x80808080;
	// out = ((in & 0x7f7f7f7f) << 1) ^ ((mask - (mask >> 7)) & 0x1b1b1b1b);
	*/

	mov r2, r4
	ands r2, r0 // mask

	mov r3, r4 // need to preserve S{1}

	bics r3, r0 // can also eors r2
	lsls r3, #1

	lsrs r2, #7
	muls r2, r1  // get predicated reduction

	eors r2, r3 // S{2}

	ands r0, r2 // mask

	mov r3, r2 // need to preserve S{2}

	eors r3, r0
	lsls r3, #1

	lsrs r0, #7
	muls r0, r1 // get predicated reduction

	eors r3, r0 // S{4}

	mov r0, r10 // get 0x80808080 back
	ands r0, r3 // mask

	lsrs r0, #7
	muls r0, r1

	mov r1, r10 // get 0x80808080 back
	mvns r1, r1 // can't use mask, can't bics into the input data
	ands r1, r3
	lsls r1, #1
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
	mov r0, r10 // 0x80808080
	movs r1, 0x1b

	mov r2, r5
	ands r2, r0 // mask

	mov r3, r5 // need to preserve S{1}

	bics r3, r0 // can also eors r2
	lsls r3, #1

	lsrs r2, #7
	muls r2, r1  // get predicated reduction

	eors r2, r3 // S{2}

	ands r0, r2 // mask

	mov r3, r2 // need to preserve S{2}

	eors r3, r0
	lsls r3, #1

	lsrs r0, #7
	muls r0, r1 // get predicated reduction

	eors r3, r0 // S{4}

	mov r0, r10 // get 0x80808080 back
	ands r0, r3 // mask

	lsrs r0, #7
	muls r0, r1

	mov r1, r10 // get 0x80808080 back
	mvns r1, r1 // can't use mask, can't bics into the input data
	ands r1, r3
	lsls r1, #1
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

	eors r5, r3// s0{e}^s1{b}^s2{d}^s3{9} | s1{e}^s2{b}^s3{d}^s0{9} | s2{e}^s3{b}^s0{d}^s1{9} | s3{e}^s0{b}^s1{d}^s2{9}

	//col 2
	mov r0, r10 // 0x80808080
	movs r1, 0x1b

	mov r2, r6
	ands r2, r0 // mask

	mov r3, r6 // need to preserve S{1}

	bics r3, r0 // can also eors r2
	lsls r3, #1

	lsrs r2, #7
	muls r2, r1  // get predicated reduction

	eors r2, r3 // S{2}

	ands r0, r2 // mask

	mov r3, r2 // need to preserve S{2}

	eors r3, r0
	lsls r3, #1

	lsrs r0, #7
	muls r0, r1 // get predicated reduction

	eors r3, r0 // S{4}

	mov r0, r10 // get 0x80808080 back
	ands r0, r3 // mask

	lsrs r0, #7
	muls r0, r1

	mov r1, r10 // get 0x80808080 back
	mvns r1, r1 // can't use mask, can't bics into the input data
	ands r1, r3
	lsls r1, #1
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
	mov r0, r10 // 0x80808080
	mov r0, r10 // 0x80808080
	movs r1, 0x1b

	mov r2, r7
	ands r2, r0 // mask

	mov r3, r7 // need to preserve S{1}

	bics r3, r0 // can also eors r2
	lsls r3, #1

	lsrs r2, #7
	muls r2, r1  // get predicated reduction

	eors r2, r3 // S{2}

	ands r0, r2 // mask

	mov r3, r2 // need to preserve S{2}

	eors r3, r0
	lsls r3, #1

	lsrs r0, #7
	muls r0, r1 // get predicated reduction

	eors r3, r0 // S{4}

	mov r0, r10 // get 0x80808080 back
	ands r0, r3 // mask

	lsrs r0, #7
	muls r0, r1

	mov r1, r10 // get 0x80808080 back
	mvns r1, r1 // can't use mask, can't bics into the input data
	ands r1, r3
	lsls r1, #1
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

	mov r0, r9 // get inv_sbox for next round or final round

	cmp r14, r12
	beq 2f // if rk reached final condition
	b 1b // out of range for conditional branch

2:	//final round

	//saved 2 cycles on rev16 // lost 2 cycles on inv_sbox pressured out, 1 on extra mov

	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 | s33

	//final
	// r4 - s00`| s13`| s22`| s31`
	// r5 - s01`| s10`| s23`| s32`
	// r6 - s02`| s11`| s20`| s33`
	// r7 - s03`| s12`| s21`| s30`

	lsrs r1, r4, #24
	ldrb r1, [r0, r1]
	lsls r1, #24

	rev16 r3, r7

	// r0 - inv_sbox
	// r1 -     |     |     | s30`
	// r2 -
	// r3 - s13 |  -  |  -  | s23

	// r4 - s00 | s10 | s20 |  -
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 |  -  |  -  | s33

	lsrs r2, r7, #24
	ldrb r2, [r0, r2]
	lsls r2, #24

	uxtb r7, r7
	ldrb r7, [r0, r7]

	orrs r7, r1

	// r0 - inv_sbox
	// r1 -
	// r2 -     |     |     | s33`
	// r3 - s13 |  -  |  -  | s23

	// r4 - s00 | s10 | s20 |  -
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03`|  -  |  -  | s30`

	lsrs r1, r6, #8
	uxtb r1, r1
	ldrb r1, [r0, r1]
	lsls r1, #8

	orrs r7, r1

	lsrs r1, r5, #16
	uxtb r1, r1
	ldrb r1, [r0, r1]
	lsls r1, #16

	orrs r7, r1

	// r0 - inv_sbox
	// r1 -
	// r2 -     |     |     | s33`
	// r3 - s13 |  -  |  -  | s23

	// r4 - s00 | s10 | s20 |  -
	// r5 - s01 | s11 |  -  | s31
	// r6 - s02 |  -  | s22 | s32
	// r7 - s03`| s12`| s21`| s30`

	lsrs r1, r5, #8
	uxtb r1, r1
	ldrb r1, [r0, r1]
	lsls r1, #8

	orrs r2, r1

	// r0 - inv_sbox
	// r1 -
	// r2 -     | s11`|     | s33`
	// r3 - s13 |  -  |  -  | s23

	// r4 - s00 | s10 | s20 |  -
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02 |  -  | s22 | s32
	// r7 - s03`| s12`| s21`| s30`

	// A :ror16 from r4 ?
	// B :mov from r6 ?

	mov r1, r6 // free up s02

	uxtb r6, r6
	ldrb r6, [r0, r6]

	orrs r6, r2

	// r0 - inv_sbox
	// r1 -  -  |  -  | s22 | s32
	// r2 -
	// r3 - s13 |  -  |  -  | s23

	// r4 - s00 | s10 | s20 |  -
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02`| s11`|  -  | s33`
	// r7 - s03`| s12`| s21`| s30`

	lsrs r2, r3, #24
	ldrb r2, [r0, r2]
	lsls r2, #16

	uxtb r3, r3
	ldrb r3, [r0, r3]
	lsls r3, #8

	// r0 - inv_sbox
	// r1 -  -  |  -  | s22 | s32
	// r2 -     |     | s23`|
	// r3 -     | s13`|     |

	// r4 - s00 | s10 | s20 |  -
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02`| s11`|  -  | s33`
	// r7 - s03`| s12`| s21`| s30`

	lsrs r0, r1, #24 // too high pressure
	add r0, r9 // add inv_sbox base
	ldrb r0, [r0]
	lsls r0, #24

	orrs r2, r0

	mov r0, r9 // get inv_sbox back

	// r0 - inv_sbox
	// r1 -  -  |  -  | s22 |  -
	// r2 -     |     | s23`| s32`
	// r3 -     | s13`|     |

	// r4 - s00 | s10 | s20 |  -
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02`| s11`|  -  | s33`
	// r7 - s03`| s12`| s21`| s30`

	lsrs r1, #16
	uxtb r1, r1
	ldrb r1, [r0, r1]
	lsls r1, #16

	orrs r3, r1

	// r0 - inv_sbox
	// r1 -
	// r2 -     |     | s23`| s32`
	// r3 -     | s13`| s22`|

	// r4 - s00 | s10 | s20 |  -
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02`| s11`|  -  | s33`
	// r7 - s03`| s12`| s21`| s30`

	rev16 r1, r4

	uxtb r4, r4
	ldrb r4, [r0, r4]

	orrs r4, r3

	lsrs r3, r5, #24
	ldrb r3, [r0, r3]
	lsls r3, #24

	orrs r4, r3

	// r0 - inv_sbox
	// r1 - s10 |     |     | s20
	// r2 -     |     | s23`| s32`
	// r3 -

	// r4 - s00`| s13`| s22`| s31`
	// r5 - s01 |  -  |  -  |  -
	// r6 - s02`| s11`|  -  | s33`
	// r7 - s03`| s12`| s21`| s30`

	uxtb r5, r5
	ldrb r5, [r0, r5]

	orrs r5, r2

	lsrs r3, r1, #24
	ldrb r3, [r0, r3]
	lsls r3, #16

	orrs r6, r3

	uxtb r1, r1
	ldrb r1, [r0, r1]
	lsls r1, #8

	orrs r5, r1

	//final addroundkey
	add r14, r8 // decrement rk
	mov r0, r14 // get rk

	ldm r0, {r0-r3}
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