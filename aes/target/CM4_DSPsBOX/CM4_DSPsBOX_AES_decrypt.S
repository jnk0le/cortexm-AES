/*!
 * \file CM4_DSPsBOX_AES_decrypt.S
 * \brief ?
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date Dec 2018
 */

.syntax unified
.thumb
.text

.align 3
// void CM4_DSPsBOX_AES_decrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM4_DSPsBOX_AES_decrypt
.type   CM4_DSPsBOX_AES_decrypt,%function
CM4_DSPsBOX_AES_decrypt:
#if __ARM_ARCH_7EM__
	adds r0, #16 //to compare against before final round
	push {r0,r2,r4-r11,lr} //stack rk+16, out

	//rk_end = rk+16 + rounds * 16
	add r14, r0, r3, lsl #4

	//load input
	ldmia r1!, {r4-r7}

	//load initial round key
	ldmdb r14!, {r0-r3}

	//initial addroundkey
	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	movw r7, #:lower16:AES_inv_sbox
	movt r7, #:upper16:AES_inv_sbox

1:	//inv shiftrows and subbytes
	//row 2 - ST2x
	uxtb r4, r2, ror #16
	uxtb r5, r3, ror #16
	uxtb r6, r0, ror #16
	uxtb r12, r1, ror #16

	//row 3 - ST3x
	uxtb r8, r1, ror #24
	uxtb r9, r2, ror #24
	uxtb r10, r3, ror #24
	uxtb r11, r0, ror #24

	//halfway sboxing
	ldrb r4, [r7, r4]
	ldrb r5, [r7, r5]
	ldrb r12, [r7, r12]
	ldrb r8, [r7, r8]
	ldrb r9, [r7, r9]
	ldrb r10, [r7, r10]
	ldrb r11, [r7, r11]
	ldrb r6, [r7, r6] // put after high reg loads to realign wide ldrs

	//repack upper part (keep in bottom half)
	orr r8, r4, r8, lsl #8
	orr r9, r5, r9, lsl #8
	orr r10, r6, r10, lsl #8
	orr r11, r12, r11, lsl #8

	//row 1 - ST1x
	uxtb r4, r3, ror #8
	uxtb r5, r0, ror #8
	uxtb r6, r1, ror #8
	uxtb r12, r2, ror #8

	//row 0 - ST0x
	uxtb r0, r0
	uxtb r1, r1
	uxtb r2, r2
	uxtb r3, r3

	//rest of the sboxing
	ldrb r0, [r7, r0]
	ldrb r1, [r7, r1]
	ldrb r2, [r7, r2]
	ldrb r3, [r7, r3]
	ldrb r4, [r7, r4]
	ldrb r5, [r7, r5]
	ldrb r6, [r7, r6]
	ldrb r12, [r7, r12]

	//repack bottom part
	orr r0, r0, r4, lsl #8
	orr r1, r1, r5, lsl #8
	orr r2, r2, r6, lsl #8
	orr r3, r3, r12, lsl #8

	//repack wholly // orr??
	pkhbt r0, r0, r8, lsl #16
	pkhbt r1, r1, r9, lsl #16
	pkhbt r2, r2, r10, lsl #16
	pkhbt r3, r3, r11, lsl #16

	//addroundkey
	ldr r4, [r14, #-16]!
	ldr r12, [sp] // load also final address to compare later // also split pre indexed load with its dependencies
	ldr r5, [r14, #4]
	ldr r6, [r14, #8]
	ldr r8, [r14, #12]

	eors r0, r4
	eors r1, r5
	eor r2, r6
	eor r3, r8

	//do inv mix columns as
	// tmp = 09 * (s0^s1^s2^s3) // (s0^s1^s2^s3) ^ gmul2(gmul2(gmul2(s0^s1^s2^s3)))
	// s0` ^= tmp ^ gmul2(gmul2(s0^s2)) ^ gmul2(s0^s1) // s0` = s1^s2^s3 ^ gmul8(s0^s1^s2^s3) ^ gmul2(gmul2(s0^s2)) ^ gmul2(s0^s1)
	// s1` ^= tmp ^ gmul2(gmul2(s1^s3)) ^ gmul2(s1^s2) // s1` = s0^s2^s3 ^ gmul8(s0^s1^s2^s3) ^ gmul2(gmul2(s1^s3)) ^ gmul2(s1^s2)
	// s2` ^= tmp ^ gmul2(gmul2(s0^s2)) ^ gmul2(s2^s3) // s2` = s0^s1^s3 ^ gmul8(s0^s1^s2^s3) ^ gmul2(gmul2(s0^s2)) ^ gmul2(s2^s3)
	// s3` ^= tmp ^ gmul2(gmul2(s1^s3)) ^ gmul2(s3^s0) // s3` = s0^s1^s2 ^ gmul8(s0^s1^s2^s3) ^ gmul2(gmul2(s1^s3)) ^ gmul2(s3^s0)

	//col 0 - STx0
	eor r4, r0, r0, ror #8 // r4 = s0^s1 | s1^s2 | s2^s3 | s3^s0
	eor r5, r0, r0, ror #16 // r5 = s0^s2 | s1^s3 | s0^s2 | s1^s3
	eor r6, r4, r4, ror #16 // r6 = s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	eor r10, r4, r0, ror #16 // r10 = s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3

	//perform quad gfmul in constant time

	//tmp
	uadd8 r8, r6, r6 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r6, r9, r8 // if uadd carried then take reduced byte

	uadd8 r8, r6, r6 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r6, r9, r8 // if uadd carried then take reduced byte

	uadd8 r8, r6, r6 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r6, r9, r8 // if uadd carried then take reduced byte

	eor r6, r6, r10, ror #8 // effective r10 = s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	//gmul2(gmul2())
	uadd8 r8, r5, r5 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r5, r9, r8 // if uadd carried then take reduced byte

	uadd8 r8, r5, r5 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r5, r9, r8 // if uadd carried then take reduced byte

	eors r6, r5

	//gmul2()
	uadd8 r8, r4, r4 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r4, r9, r8 // if uadd carried then take reduced byte

	eor r0, r4, r6

	//col 1 - STx1
	eor r4, r1, r1, ror #8 // r4 = s0^s1 | s1^s2 | s2^s3 | s3^s0
	eor r5, r1, r1, ror #16 // r5 = s0^s2 | s1^s3 | s0^s2 | s1^s3
	eor r6, r4, r4, ror #16 // r6 = s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	eor r10, r4, r1, ror #16 // r10 = s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3

	//perform quad gfmul in constant time

	//tmp
	uadd8 r8, r6, r6 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r6, r9, r8 // if uadd carried then take reduced byte

	uadd8 r8, r6, r6 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r6, r9, r8 // if uadd carried then take reduced byte

	uadd8 r8, r6, r6 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r6, r9, r8 // if uadd carried then take reduced byte

	eor r6, r6, r10, ror #8 // effective r10 = s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	//gmul2(gmul2())
	uadd8 r8, r5, r5 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r5, r9, r8 // if uadd carried then take reduced byte

	uadd8 r8, r5, r5 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r5, r9, r8 // if uadd carried then take reduced byte

	eors r6, r5

	//gmul2()
	uadd8 r8, r4, r4 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r4, r9, r8 // if uadd carried then take reduced byte

	eor r1, r4, r6

	//col 2 - STx2
	eor r4, r2, r2, ror #8 // r4 = s0^s1 | s1^s2 | s2^s3 | s3^s0
	eor r5, r2, r2, ror #16 // r5 = s0^s2 | s1^s3 | s0^s2 | s1^s3
	eor r6, r4, r4, ror #16 // r6 = s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	eor r10, r4, r2, ror #16 // r10 = s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3

	//perform quad gfmul in constant time

	//tmp
	uadd8 r8, r6, r6 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r6, r9, r8 // if uadd carried then take reduced byte

	uadd8 r8, r6, r6 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r6, r9, r8 // if uadd carried then take reduced byte

	uadd8 r8, r6, r6 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r6, r9, r8 // if uadd carried then take reduced byte

	eor r6, r6, r10, ror #8 // effective r10 = s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	//gmul2(gmul2())
	uadd8 r8, r5, r5 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r5, r9, r8 // if uadd carried then take reduced byte

	uadd8 r8, r5, r5 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r5, r9, r8 // if uadd carried then take reduced byte

	eors r6, r5

	//gmul2()
	uadd8 r8, r4, r4 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r4, r9, r8 // if uadd carried then take reduced byte

	eor r2, r4, r6

	//col 3 - STx3
	eor r4, r3, r3, ror #8 // r4 = s0^s1 | s1^s2 | s2^s3 | s3^s0
	eor r5, r3, r3, ror #16 // r5 = s0^s2 | s1^s3 | s0^s2 | s1^s3
	eor r6, r4, r4, ror #16 // r6 = s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	eor r10, r4, r3, ror #16 // r10 = s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3

	//perform quad gfmul in constant time

	//tmp
	uadd8 r8, r6, r6 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r6, r9, r8 // if uadd carried then take reduced byte

	uadd8 r8, r6, r6 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r6, r9, r8 // if uadd carried then take reduced byte

	uadd8 r8, r6, r6 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r6, r9, r8 // if uadd carried then take reduced byte

	eor r6, r6, r10, ror #8 // effective r10 = s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	//gmul2(gmul2())
	uadd8 r8, r5, r5 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r5, r9, r8 // if uadd carried then take reduced byte

	uadd8 r8, r5, r5 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r5, r9, r8 // if uadd carried then take reduced byte

	eors r6, r5

	//gmul2()
	uadd8 r8, r4, r4 // quad lsl #1
	eor r9, r8, #0x1b1b1b1b
	sel r4, r9, r8 // if uadd carried then take reduced byte

	eor r3, r4, r6

	cmp.w r12, r14
	bne.w 1b

	//final round
	//row 2 - ST2x
	uxtb r4, r2, ror #16
	uxtb r5, r3, ror #16
	uxtb r6, r0, ror #16
	uxtb r12, r1, ror #16

	//row 3 - ST3x
	uxtb r8, r1, ror #24
	uxtb r9, r2, ror #24
	uxtb r10, r3, ror #24
	uxtb r11, r0, ror #24

	//halfway sboxing
	ldrb r4, [r7, r4]
	ldrb r5, [r7, r5]
	ldrb r12, [r7, r12]
	ldrb r8, [r7, r8]
	ldrb r9, [r7, r9]
	ldrb r10, [r7, r10]
	ldrb r11, [r7, r11]
	ldrb r6, [r7, r6] // put after high reg loads to realign wide ldrs

	//repack upper part (keep in bottom half)
	orr r8, r4, r8, lsl #8
	orr r9, r5, r9, lsl #8
	orr r10, r6, r10, lsl #8
	orr r11, r12, r11, lsl #8

	//row 1 - ST1x
	uxtb r4, r3, ror #8
	uxtb r5, r0, ror #8
	uxtb r6, r1, ror #8
	uxtb r12, r2, ror #8

	//row 0 - ST0x
	uxtb r0, r0
	uxtb r1, r1
	uxtb r2, r2
	uxtb r3, r3

	//rest of the sboxing
	ldrb r0, [r7, r0]
	ldrb r1, [r7, r1]
	ldrb r2, [r7, r2]
	ldrb r3, [r7, r3]
	ldrb r4, [r7, r4]
	ldrb r5, [r7, r5]
	ldrb r6, [r7, r6]
	ldrb r12, [r7, r12]

	//repack bottom part
	orr r0, r0, r4, lsl #8
	orr r1, r1, r5, lsl #8
	orr r2, r2, r6, lsl #8
	orr r3, r3, r12, lsl #8

	//repack wholly // orr??
	pkhbt r0, r0, r8, lsl #16
	pkhbt r1, r1, r9, lsl #16
	pkhbt r2, r2, r10, lsl #16
	pkhbt r3, r3, r11, lsl #16

	//final addroudkey
	ldr r4, [r14, #-16]!
	ldr r7, [sp, #4] // load output pointer
	ldr r5, [r14, #4]
	ldr r6, [r14, #8]
	ldr r8, [r14, #12]

	add sp, #8

	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r8

	str r0, [r7]
	str r1, [r7, #4]
	str r2, [r7, #8]
	str r3, [r7, #12]

	pop {r4-r11,pc}

#else
	//crash in case the function was called on non dsp cortex m3
	b .
#endif
