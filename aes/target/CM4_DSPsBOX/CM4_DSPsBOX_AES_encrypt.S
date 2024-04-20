/*!
 * \file CM4_DSPsBOX_AES_encrypt.S
 * \brief
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 * \date Dec 2018
 */

// compile for compatible targets only
#if __ARM_EABI__ && __thumb2__ && __ARM_FEATURE_DSP

.syntax unified
.thumb
.text

.align 3
// void CM4_DSPsBOX_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM4_DSPsBOX_AES_encrypt
.type   CM4_DSPsBOX_AES_encrypt,%function
CM4_DSPsBOX_AES_encrypt:
	add r3, r0, r3, lsl #4 //rk_end-16 = rk + rounds * 16
	push {r2,r3,r4-r11,lr} //stack out, rk_end-16

	mov r14, r0

	//load input
	ldmia r1!, {r4-r7}
	//load key
	ldmia r14!, {r0-r3}

	//initial addroundkey
	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	movw r7, #:lower16:AES_sbox
	movt r7, #:upper16:AES_sbox

1:	//shiftrows and subbytes
	//row 2 - ST2x
	uxtb r8, r2, ror #16
	uxtb r9, r3, ror #16
	uxtb r10, r0, ror #16
	uxtb r11, r1, ror #16

	//row 3 - ST3x
	lsrs r4, r3, #24
	lsrs r5, r0, #24
	lsrs r6, r1, #24
	uxtb r12, r2, ror #24

	//halfway sboxing
	ldrb r4, [r7, r4]
	ldrb r5, [r7, r5]
	ldrb r6, [r7, r6]
	ldrb r12, [r7, r12]
	ldrb r8, [r7, r8]
	ldrb r9, [r7, r9]
	ldrb r10, [r7, r10]
	ldrb r11, [r7, r11]

	//repack upper part (keep in bottom half)
	orr r8, r8, r4, lsl #8
	orr r9, r9, r5, lsl #8
	orr r10, r10, r6, lsl #8
	orr r11, r11, r12, lsl #8

	//row 1 - ST1x
	uxtb r4, r1, ror #8
	uxtb r5, r2, ror #8
	uxtb r6, r3, ror #8
	uxtb r12, r0, ror #8

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
	ldrb.w r6, [r7, r6] // loses cycles if .n below r12 load // align next load
	ldrb r12, [r7, r12]

	//repack bottom part
	orr r0, r0, r4, lsl #8
	orr r1, r1, r5, lsl #8
	orr r2, r2, r6, lsl #8
	orr r3, r3, r12, lsl #8

	//repack wholly
	orr r0, r0, r8, lsl #16
	orr r1, r1, r9, lsl #16
	orr r2, r2, r10, lsl #16
	orr r3, r3, r11, lsl #16

	// do mix columns as
	// tmp = s0 ^ s1 ^ s2 ^ s3
	// s0` ^= tmp ^ gmul2(s0^s1) // s1^s2^s3^gmul2(s0^s1)
	// s1` ^= tmp ^ gmul2(s1^s2) // s0^s2^s3^gmul2(s1^s2)
	// s2` ^= tmp ^ gmul2(s2^s3) // s0^s1^s3^gmul2(s2^s3)
	// S3` ^= tmp ^ gmul2(s3^s0) // s0^s1^s2^gmul2(s3^s0)

	//col 0 - STx0
	eor r4, r0, r0, ror #8 // r4 = s0^s1 | s1^s2 | s2^s3 | s3^s0
	//eor r5, r4, r4, ror #16 // r5 = s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	//eor r5, r5, r0 // r5 = s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2
	eor r5, r4, r0, ror #16 // r5 = s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3

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

	//addroundkey
	// aggregate loads by source in case it lies in different memory blocks
	ldr r5, [r14, #4]
	ldr r8, [r14, #8]
	ldr r9, [r14, #12]
	ldr r4, [r14], #16
	ldr r6, [sp, #4] // get final condition

	eors r0, r4
	eors r1, r5

	cmp r6, r14

	eor.w r2, r8
	eor.w r3, r9

	bne.w 1b // out of range

	//final round
	//row 2 - ST2x
	uxtb r8, r2, ror #16
	uxtb r9, r3, ror #16
	uxtb r10, r0, ror #16
	uxtb r11, r1, ror #16

	//row 3 - ST3x
	lsrs r4, r3, #24
	lsrs r5, r0, #24
	lsrs r6, r1, #24
	uxtb r12, r2, ror #24

	//halfway sboxing
	ldrb r4, [r7, r4]
	ldrb r5, [r7, r5]
	ldrb r6, [r7, r6]
	ldrb r12, [r7, r12]
	ldrb r8, [r7, r8]
	ldrb r9, [r7, r9]
	ldrb r10, [r7, r10]
	ldrb r11, [r7, r11]

	//repack upper part (keep in bottom half)
	orr r8, r8, r4, lsl #8
	orr r9, r9, r5, lsl #8
	orr r10, r10, r6, lsl #8
	orr r11, r11, r12, lsl #8

	//row 1 - ST1x
	uxtb r4, r1, ror #8
	uxtb r5, r2, ror #8
	uxtb r6, r3, ror #8
	uxtb r12, r0, ror #8

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
	ldrb.w r6, [r7, r6] // align next load
	ldrb r12, [r7, r12]

	//repack bottom part
	orr r0, r0, r4, lsl #8
	orr r1, r1, r5, lsl #8
	orr r2, r2, r6, lsl #8
	orr r3, r3, r12, lsl #8

	//repack wholly
	orr r0, r0, r8, lsl #16
	orr r1, r1, r9, lsl #16
	orr r2, r2, r10, lsl #16
	orr r3, r3, r11, lsl #16

	ldr r7, [sp], #8 // load output pointer and clear stack

	//final addroudkey
	ldr r4, [r14]
	ldr r5, [r14, #4]
	ldr r6, [r14, #8]
	ldr r8, [r14, #12]

	eors r0, r4
	eors r1, r5
	eors r2, r6
	eor.w r3, r8

	str r0, [r7]
	str r1, [r7, #4]
	str r2, [r7, #8]
	str r3, [r7, #12]

	pop {r4-r11,pc}

#endif
