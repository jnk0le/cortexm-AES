/*!
 * \file CM0_FASTMULsBOX_AES_encrypt.S
 * \brief faster than standard version, only when running on core with 1 cycle multiplier
 *
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date 25 oct 2021
 */

.syntax unified
.thumb
.text

.align 2
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

	ldr r6, =0x80808080
	mov r10, r6 // 0x80808080

	//rk_end-16 = rk + rounds * 16
	lsls r3, r3, #4
	adds r3, r0
	mov r12, r3 // final ptr

	ldmia r0!, {r4-r7} // load key
	mov r14, r0 // already incremented

	ldm r1, {r0-r3} // load input

	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	// r8 - increment constant
	// r9 - sbox
	// r10 - 0x80808080
	// r11 - x
	// r12 - final ptr
	// r14 - current ptr

	mov r0, r9 // get sbox here to align loop entry, next getter is at the end of loop

1:	//shiftrows and subbytes

	//r1,r2,r3 are free //saved 2 cycles on rev 16// lost 2 cycles on sbox pressured out + 1 unoptimized mov // maybe try it more straightforward
	//columns are kept as little endian so right/left in shifts is in reverse wrt transposed canonical state representation

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
	lsls r1, r1, #24

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
	lsls r2, r2, #8

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

	lsrs r3, r3, #24
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
	lsls r3, r3, #24

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
	lsls r3, r3, #16

	orrs r1, r3

	// r0 - sbox
	// r1 -     | s11`| s22`| s33`
	// r2 - s13 |  -  |  -  | s23
	// r3 -

	// r4 - s00 | s10 | s20 | s30
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02 | s12 |  -  |  -
	// r7 - s03`|     | s21`| s32`

	//give up on rev16 // column 0 goes into r3 // correct later in mixcolumns??

	uxtb r3, r4
	ldrb r3, [r0, r3]

	orrs r3, r1

	lsrs r1, r4, #8
	uxtb r1, r1
	ldrb r1, [r0, r1]
	lsls r1, r1, #8

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
	lsls r1, r1, #24

	lsrs r4, r4, #16
	uxtb r4, r4
	ldrb r4, [r0, r4]
	lsls r4, r4, #16

	// r0 - sbox
	// r1 -     |     |     | s30`
	// r2 - s13 |  -  |  -  | s23
	// r3 - s00`| s11`| s22`| s33`

	// r4 -     |     | s20`|
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02 | s12 |  -  |  -
	// r7 - s03`| s10`| s21`| s32`

	lsrs r0, r5, #24 // to high pressure

	uxtb r5, r5
	add r5, r9 // add sbox base
	ldrb r5, [r5]

	orrs r5, r1

	mov r1, r9 // get sbox back
	ldrb r0, [r1, r0]
	lsls r0, r0, #24

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
	lsls r0, r0, #16

	orrs r5, r0

	// r0 -     |     |     |
	// r1 - sbox
	// r2 - s13 |  -  |  -  |  -
	// r3 - s00`| s11`| s22`| s33`

	// r4 -     |     | s20`| s31`
	// r5 - s01`|     | s23`| s30`
	// r6 - s02 | s12 |  -  |  -
	// r7 - s03`| s10`| s21`| s32`

	uxtb r2, r2
	ldrb r2, [r1, r2]
	lsls r2, r2, #8

	lsrs r0, r6, #8
	uxtb r0, r0
	ldrb r0, [r1, r0]
	lsls r0, r0, #8

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

	//mov r4, r3 // position fixed later in mixcolums

	// do mix columns as
	// tmp = s0 ^ s1 ^ s2 ^ s3
	// s0` ^= tmp ^ gmul2(s0^s1) // s1^s2^s3^gmul2(s0^s1)
	// s1` ^= tmp ^ gmul2(s1^s2) // s0^s2^s3^gmul2(s1^s2)
	// s2` ^= tmp ^ gmul2(s2^s3) // s0^s1^s3^gmul2(s2^s3)
	// S3` ^= tmp ^ gmul2(s3^s0) // s0^s1^s2^gmul2(s3^s0)

	// use approach with 1 more xor instead of rotation

	mov r0, r10 // 0x80808080
	movs r1, #0x1b

	// 2 registers + 1 in/out are free // column 0 comes in r3 insteadof r4, need to correct it's position before mul

	//col 0
	lsrs r2, r3, #8
	lsls r4, r3, #24
	orrs r2, r4

	eors r2, r3 // s0^s1 | s1^s2 | s2^s3 | s3^s0

	rev16 r4, r2 //ror #16
	rev r4, r4 //ror #16

	eors r4, r2 // s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	eors r4, r3 // s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	//now mult r2 and eors it into r4 // r3 free

	/* do quad multiplication according to:
	// out = ((in & 0x7f7f7f7f) << 1) ^ (((in & 0x80808080) >> 7)) * 0x1b);

	(in & 0x7f7f7f7f) - can be gotten in 2 ways - bics from 0x80808080 or xor with `mask` (in & 0x80808080)
	*/

	mov r3, r2
	ands r3, r0 // mask

	bics r2, r0 // can also eors r3
	lsls r2, r2, #1

	lsrs r3, r3, #7
	muls r3, r1 // get predicated reduction

	eors r2, r3 // reduce
	eors r4, r2 // final

	//col 1
	lsrs r2, r5, #8
	lsls r3, r5, #24
	orrs r2, r3

	eors r2, r5 // s0^s1 | s1^s2 | s2^s3 | s3^s0

	rev16 r3, r2
	rev r3, r3

	eors r3, r2 // s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	eors r5, r3 // s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	mov r3, r2
	ands r3, r0 //mask

	bics r2, r0 // can also eors r3
	lsls r2, r2, #1

	lsrs r3, r3, #7
	muls r3, r1 // get predicated reduction

	eors r2, r3 // reduce
	eors r5, r2 // final

	//col 2
	lsrs r2, r6, #8
	lsls r3, r6, #24
	orrs r2, r3

	eors r2, r6 // s0^s1 | s1^s2 | s2^s3 | s3^s0

	rev16 r3, r2
	rev r3, r3

	eors r3, r2 // s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	eors r6, r3 // s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	mov r3, r2
	ands r3, r0 //mask

	bics r2, r0 // can also eors r3
	lsls r2, r2, #1

	lsrs r3, r3, #7
	muls r3, r1 // get predicated reduction

	eors r2, r3 // reduce
	eors r6, r2 // final

	//col 3
	lsrs r2, r7, #8
	lsls r3, r7, #24
	orrs r2, r3

	eors r2, r7 // s0^s1 | s1^s2 | s2^s3 | s3^s0

	rev16 r3, r2
	rev r3, r3

	eors r3, r2 // s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	eors r7, r3 // s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	mov r3, r2
	ands r3, r0 //mask

	bics r2, r0 // can also eors r3
	lsls r2, r2, #1

	lsrs r3, r3, #7
	muls r3, r1 // get predicated reduction

	eors r2, r3 // reduce
	eors r7, r2 // final

	//addroundkey
	mov r0, r14 // get current rk
	add r14, r8 // increment rk by 16

	ldm r0, {r0-r3}
	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	mov r0, r9 // get sbox for next round or final round

	cmp r14, r12
	beq 2f // if rk reached final condition
	b 1b // out of range for conditional branch

2:	//final round

	//r1,r2,r3 are free //saved 2 cycles on rev 16// lost 2 cycles on sbox pressured out // maybe try it more straightforward
	//columns are kept as little endian so right/left in shifts is in reverse wrt transposed canonical state representation

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
	lsls r1, r1, #24

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
	lsls r2, r2, #8

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

	lsrs r3, r3, #24
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
	lsls r3, r3, #24

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
	lsls r3, r3, #16

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
	lsls r1, r1, #8

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
	lsls r1, r1, #24

	lsrs r4, r4, #16
	uxtb r4, r4
	ldrb r4, [r0, r4]
	lsls r4, r4, #16

	// r0 - sbox
	// r1 -     |     |     | s30`
	// r2 - s13 |  -  |  -  | s23
	// r3 - s00`| s11`| s22`| s33`

	// r4 -     |     | s20`|
	// r5 - s01 |  -  |  -  | s31
	// r6 - s02 | s12 |  -  |  -
	// r7 - s03`| s10`| s21`| s32`

	lsrs r0, r5, #24 // to high pressure

	uxtb r5, r5
	add r5, r9 // add sbox base
	ldrb r5, [r5]

	orrs r5, r1

	mov r1, r9 // get sbox back
	ldrb r0, [r1, r0]
	lsls r0, r0, #24

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
	lsls r0, r0, #16

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
	lsls r2, r2, #8

	lsrs r0, r6, #8
	uxtb r0, r0
	ldrb r0, [r1, r0]
	lsls r0, r0, #8

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

	pop {r0-r2} // pop to non data
	mov r8, r0
	mov r9, r1
	mov r10, r2

	pop {r0} // unstack out pointer
	stmia r0!, {r3,r5-r7}

	pop {r4-r7, pc}
