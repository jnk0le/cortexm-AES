/*!
 * \file CM4_DSPsBOX_AES_encrypt.S
 * \brief cortex-m4 optimized aes encryption
 *
 * utilizes basic sbox table
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only
#if __ARM_EABI__ && __thumb2__ && __ARM_FEATURE_DSP

.syntax unified
.thumb
.text

.balign 4
// void CM4_DSPsBOX_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM4_DSPsBOX_AES_encrypt
.type   CM4_DSPsBOX_AES_encrypt,%function
CM4_DSPsBOX_AES_encrypt:
	push {r2,r4-r11,lr} //stack out

	add r11, r0, r3, lsl #4 // rk_end-16 = rk + rounds * 16
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

	movw r7, #:lower16:AES_sbox
	movt r7, #:upper16:AES_sbox

	// global allocation
	// r7 - sbox
	// r11 - final ptr
	// r12 - current rk ptr

	// r0 - s00 | s10 | s20 | s30
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33

	//final
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02`| s13`| s20`| s31`
	// r7 - s03`| s10`| s21`| s32`

1: // shiftrows and subbytes
	uxtb r4, r0
	lsrs r6, r3, #24
	uxtb.w r9, r1, ror #8
	uxtb.w r10, r2, ror #16
	uxtb r5, r1
	uxtb r8, r2, ror #8
	uxtb r14, r3, ror #16

	ldrb r4, [r7, r4]
	ldrb r6, [r7, r6]
	ldrb r5, [r7, r5]
	ldrb.w r9, [r7, r9]
	ldrb.w r10, [r7, r10]
	ldrb.w r8, [r7, r8]
	ldrb.w r14, [r7, r14]

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00` // c0r0
	// r5 - s01` // c1r0
	// r6 - s33` // c0r3
	// r8 - s12` // c1r1
	// r9 - s11` // c0r1
	// r10 - s22` // c0r2
	// r14 - s23` // c1r2

	orr.w r4, r4, r6, lsl #24
	orr.w r4, r4, r9, lsl #8
	orr.w r10, r4, r10, lsl #16 // keep col 0 outside lower regs
	orr.w r14, r5, r14, lsl #16
	orr.w r14, r14, r8, lsl #8

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 -
	// r5 -
	// r6 -
	// r8 -
	// r9 -
	// r10 - s00`| s11`| s22`| s33`
	// r14 - s01`| s12`| s23`|

	lsrs r4, r1, #24
	lsrs r5, r2, #24
	uxtb r8, r1, ror #16
	uxtb r9, r3, ror #8
	lsrs r1, r0, #24
	uxtb r2, r2
	uxtb r3, r3
	uxtb r6, r0, ror #16
	uxtb r0, r0, ror #8

	ldrb r4, [r7, r4]
	ldrb r5, [r7, r5]
	ldrb r1, [r7, r1]
	ldrb r2, [r7, r2]
	ldrb r3, [r7, r3]
	ldrb r6, [r7, r6]
	ldrb r0, [r7, r0]
	ldrb.w r8, [r7, r8]
	ldrb.w r9, [r7, r9]

	//current allocation
	// r0 - s10` // c3r1
	// r1 - s30` // c1r3
	// r2 - s02` // c2r0
	// r3 - s03` // c3r0
	// r4 - s31` // c2r3
	// r5 - s32` // c3r3
	// r6 - s20` // c2r2
	// r8 - s21` // c3r2
	// r9 - s13` // c2r1
	// r10 - s00`| s11`| s22`| s33`
	// r14 - s01`| s12`| s23`|

	orr.w r1, r14, r1, lsl #24
	orr.w r2, r2, r9, lsl #8
	orr.w r2, r2, r6, lsl #16
	orr.w r2, r2, r4, lsl #24
	orr.w r3, r3, r0, lsl #8
	orr.w r3, r3, r8, lsl #16
	orr.w r3, r3, r5, lsl #24

	//current allocation
	// r0 -
	// r1 - s01`| s12`| s23`| s30`
	// r2 - s02`| s13`| s20`| s31`
	// r3 - s03`| s10`| s21`| s32`
	// r4 -
	// r5 -
	// r6 -
	// r8 -
	// r9 -
	// r10 - s00`| s11`| s22`| s33` // will be corrected in mixcolumns
	// r14 -

	// do mix columns as
	// tmp = s0 ^ s1 ^ s2 ^ s3
	// s0` ^= tmp ^ gmul2(s0^s1) // s1^s2^s3^gmul2(s0^s1)
	// s1` ^= tmp ^ gmul2(s1^s2) // s0^s2^s3^gmul2(s1^s2)
	// s2` ^= tmp ^ gmul2(s2^s3) // s0^s1^s3^gmul2(s2^s3)
	// S3` ^= tmp ^ gmul2(s3^s0) // s0^s1^s2^gmul2(s3^s0)

	//col 0 - STx0
	eor r4, r10, r10, ror #8 // r4 = s0^s1 | s1^s2 | s2^s3 | s3^s0
	//eor r5, r4, r4, ror #16 // r5 = s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	//eor r5, r5, r10 // r5 = s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2
	eor r5, r4, r10, ror #16 // r5 = s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3

	//perform quad gfmul in constant time
	uadd8 r6, r4, r4 // quad lsl #1
	eor r8, r6, #0x1b1b1b1b
	sel r4, r8, r6 // if uadd carried then take reduced byte

	//eor r0, r4, r5
	eor r0, r4, r5, ror #8 // effective r5 = s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	//col 1 - STx1
	eor r4, r1, r1, ror #8 // r4 = s0^s1 | s1^s2 | s2^s3 | s3^s0
	eor r5, r4, r1, ror #16 // r5 = s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3

	//perform quad gfmul in constant time
	uadd8 r6, r4, r4 // quad lsl #1
	eor r8, r6, #0x1b1b1b1b
	sel r4, r8, r6 // if uadd carried then take reduced byte

	eor r1, r4, r5, ror #8 // effective r5 = s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	//col 2 - STx2
	eor r4, r2, r2, ror #8 // r4 = s0^s1 | s1^s2 | s2^s3 | s3^s0
	eor r5, r4, r2, ror #16 // r5 = s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3

	//perform quad gfmul in constant time
	uadd8 r6, r4, r4 // quad lsl #1
	eor r8, r6, #0x1b1b1b1b
	sel r4, r8, r6 // if uadd carried then take reduced byte

	eor r2, r4, r5, ror #8 // effective r5 = s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	//col 3 - STx3
	eor r4, r3, r3, ror #8 // r4 = s0^s1 | s1^s2 | s2^s3 | s3^s0
	eor r5, r4, r3, ror #16 // r5 = s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3

	//perform quad gfmul in constant time
	uadd8 r6, r4, r4 // quad lsl #1
	eor r8, r6, #0x1b1b1b1b
	sel r4, r8, r6 // if uadd carried then take reduced byte

	eor r3, r4, r5, ror #8 // effective r5 = s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	// addroundkey
	ldmia.w r12!, {r4-r6, r8} // load rk

	eors r0, r4
	eors r1, r5
	eors r2, r6
	eor.w r3, r8

	cmp r11, r12
	bne.n 1b

	//final round
	uxtb.w r4, r0 // align following loads
	lsrs r6, r3, #24
	uxtb.w r9, r1, ror #8
	uxtb.w r10, r2, ror #16
	uxtb r5, r1
	uxtb r8, r2, ror #8
	uxtb r14, r3, ror #16

	ldrb r4, [r7, r4]
	ldrb r6, [r7, r6]
	ldrb r5, [r7, r5]
	ldrb.w r9, [r7, r9]
	ldrb.w r10, [r7, r10]
	ldrb.w r8, [r7, r8]
	ldrb.w r14, [r7, r14]

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00` // c0r0
	// r5 - s01` // c1r0
	// r6 - s33` // c0r3
	// r8 - s12` // c1r1
	// r9 - s11` // c0r1
	// r10 - s22` // c0r2
	// r14 - s23` // c1r2

	orr.w r4, r4, r6, lsl #24
	orr.w r4, r4, r9, lsl #8
	orr.w r10, r4, r10, lsl #16 // keep col 0 outside lower regs
	orr.w r14, r5, r14, lsl #16
	orr.w r14, r14, r8, lsl #8

	//current allocation
	// r0 -  -  | s10 | s20 | s30
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 |  -  |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 -
	// r5 -
	// r6 -
	// r8 -
	// r9 -
	// r10 - s00`| s11`| s22`| s33`
	// r14 - s01`| s12`| s23`|

	lsrs r4, r1, #24
	lsrs r5, r2, #24
	uxtb r8, r1, ror #16
	uxtb r9, r3, ror #8
	lsrs r1, r0, #24
	uxtb r2, r2
	uxtb r3, r3
	uxtb r6, r0, ror #16
	uxtb r0, r0, ror #8

	ldrb r4, [r7, r4]
	ldrb r5, [r7, r5]
	ldrb r1, [r7, r1]
	ldrb r2, [r7, r2]
	ldrb r3, [r7, r3]
	ldrb r6, [r7, r6]
	ldrb r0, [r7, r0]
	ldrb.w r8, [r7, r8]
	ldrb.w r9, [r7, r9]

	//current allocation
	// r0 - s10` // c3r1
	// r1 - s30` // c1r3
	// r2 - s02` // c2r0
	// r3 - s03` // c3r0
	// r4 - s31` // c2r3
	// r5 - s32` // c3r3
	// r6 - s20` // c2r2
	// r8 - s21` // c3r2
	// r9 - s13` // c2r1
	// r10 - s00`| s11`| s22`| s33`
	// r14 - s01`| s12`| s23`|

	orr.w r1, r14, r1, lsl #24
	orr.w r2, r2, r9, lsl #8
	orr.w r2, r2, r6, lsl #16
	orr.w r2, r2, r4, lsl #24
	orr.w r3, r3, r0, lsl #8
	orr.w r3, r3, r8, lsl #16
	orr.w r3, r3, r5, lsl #24

	//current allocation
	// r0 -
	// r1 - s01`| s12`| s23`| s30`
	// r2 - s02`| s13`| s20`| s31`
	// r3 - s03`| s10`| s21`| s32`
	// r4 -
	// r5 -
	// r6 -
	// r8 -
	// r9 -
	// r10 - s00`| s11`| s22`| s33` // will be corrected in addroundkey
	// r14 -

	ldr r7, [sp], #4 // load output pointer and clear stack

	//final addroudkey
	ldr r8, [r12]
	ldr r4, [r12, #4]
	ldr r5, [r12, #8]
	ldr r6, [r12, #12]

	eor.w r0, r10, r8
	eors r1, r4
	eors r2, r5
	eors r3, r6

	// for some reason stmia is +1 cycle here
	str r0, [r7]
	str r1, [r7, #4]
	str r2, [r7, #8]
	str r3, [r7, #12]
	//stmia r7!, {r0-r3}

	pop {r4-r11,pc}

#endif
