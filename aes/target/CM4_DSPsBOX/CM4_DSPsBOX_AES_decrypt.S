/*!
 * \file CM4_DSPsBOX_AES_decrypt.S
 * \brief
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only
#if __ARM_EABI__ && __thumb2__ && __ARM_FEATURE_DSP

.syntax unified
.thumb
.text

.align 3
// void CM4_DSPsBOX_AES_decrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM4_DSPsBOX_AES_decrypt
.type   CM4_DSPsBOX_AES_decrypt,%function
CM4_DSPsBOX_AES_decrypt:
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
	uxtb r8, r2, ror #16
	uxtb r9, r3, ror #16
	uxtb r10, r0, ror #16
	uxtb r11, r1, ror #16

	//row 3 - ST3x
	lsrs r4, r1, #24
	lsrs r5, r2, #24
	lsrs r6, r3, #24
	uxtb r12, r0, ror #24

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

	//addroundkey
	// aggregate loads by source in case it lies in different memory blocks
	ldr r12, [sp] // load also final address to compare later
	ldr r5, [r14, #-12]
	ldr r6, [r14, #-8]
	ldr r8, [r14, #-4]
	ldr r4, [r14, #-16]!

	eors r0, r4
	eors r1, r5
	eors r2, r6 // realign later
	eor r3, r8

	//do invMixColumns as
	// r0 = S{1}
	// r4 = S{2}
	// r5 = S{4}
	// r6 = S{8}
	// r11 - tmp

	//perform quad gfmul in constant time

	uadd8 r4, r0, r0 // quad lsl #1
	eor r11, r4, #0x1b1b1b1b
	sel r4, r11, r4 // if uadd carried then take reduced byte

	uadd8 r5, r4, r4 // quad lsl #1
	eor r11, r5, #0x1b1b1b1b
	sel r5, r11, r5 // if uadd carried then take reduced byte

	uadd8 r6, r5, r5 // quad lsl #1
	eor r11, r6, #0x1b1b1b1b
	sel r6, r11, r6 // if uadd carried then take reduced byte

	// r0 - S{9} = S{8} ^ S{1}
	// r4 - S{b} = S{9} ^ S{2}
	// r5 - S{d} = S{9} ^ S{4}
	// r6 - S{e} = S{8} ^ S{4} ^ S{2}

	eors r0, r6 // S{9}
	eors r6, r5
	eors r6, r4 // S{e}
	eors r4, r0 // S{b}
	eors r5, r0 // S{d}

	// r0 = s0{e}^s1{b}^s2{d}^s3{9} | s1{e}^s2{b}^s3{d}^s0{9} | s2{e}^s3{b}^s0{d}^s1{9} | s3{e}^s0{b}^s1{d}^s2{9}
	eor r0, r6, r0, ror #24
	eor r0, r0, r4, ror #8
	eor r0, r0, r5, ror #16

	//col 1 - STx1
	uadd8 r4, r1, r1 // quad lsl #1
	eor r11, r4, #0x1b1b1b1b
	sel r4, r11, r4 // if uadd carried then take reduced byte

	uadd8 r5, r4, r4 // quad lsl #1
	eor r11, r5, #0x1b1b1b1b
	sel r5, r11, r5 // if uadd carried then take reduced byte

	uadd8 r6, r5, r5 // quad lsl #1
	eor r11, r6, #0x1b1b1b1b
	sel r6, r11, r6 // if uadd carried then take reduced byte

	eors r1, r6 // S{9}
	eors r6, r5
	eors r6, r4 // S{e}
	eors r4, r1 // S{b}
	eors r5, r1 // S{d}

	eor r1, r6, r1, ror #24
	eor r1, r1, r4, ror #8
	eor r1, r1, r5, ror #16

	//col 2 - STx2
	uadd8 r4, r2, r2 // quad lsl #1
	eor r11, r4, #0x1b1b1b1b
	sel r4, r11, r4 // if uadd carried then take reduced byte

	uadd8 r5, r4, r4 // quad lsl #1
	eor r11, r5, #0x1b1b1b1b
	sel r5, r11, r5 // if uadd carried then take reduced byte

	uadd8 r6, r5, r5 // quad lsl #1
	eor r11, r6, #0x1b1b1b1b
	sel r6, r11, r6 // if uadd carried then take reduced byte

	eors r2, r6 // S{9}
	eors r6, r5
	eors r6, r4 // S{e}
	eors r4, r2 // S{b}
	eors r5, r2 // S{d}

	eor r2, r6, r2, ror #24
	eor r2, r2, r4, ror #8
	eor r2, r2, r5, ror #16

	//col 3 - STx3
	uadd8 r4, r3, r3 // quad lsl #1
	eor r11, r4, #0x1b1b1b1b
	sel r4, r11, r4 // if uadd carried then take reduced byte

	uadd8 r5, r4, r4 // quad lsl #1
	eor r11, r5, #0x1b1b1b1b
	sel r5, r11, r5 // if uadd carried then take reduced byte

	uadd8 r6, r5, r5 // quad lsl #1
	eor r11, r6, #0x1b1b1b1b
	sel r6, r11, r6 // if uadd carried then take reduced byte

	eors r3, r6 // S{9}
	eors r6, r5
	eors r6, r4 // S{e}
	eors r4, r3 // S{b}
	eors r5, r3 // S{d}

	cmp r12, r14 // realigned here

	eor r3, r6, r3, ror #24
	eor r3, r3, r4, ror #8
	eor r3, r3, r5, ror #16

	bne.w 1b

	//final round
	//row 2 - ST2x
	uxtb r8, r2, ror #16
	uxtb r9, r3, ror #16
	uxtb r10, r0, ror #16
	uxtb r11, r1, ror #16

	//row 3 - ST3x
	lsrs r4, r1, #24
	lsrs r5, r2, #24
	lsrs r6, r3, #24
	uxtb r12, r0, ror #24

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
	ldrb.w r6, [r7, r6] // loses cycle if .n below r12 load // align next load
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

	//final addroudkey
	ldr r4, [r14, #-16]
	ldr r5, [r14, #-12]
	ldr r6, [r14, #-8]
	ldr r8, [r14, #-4]

	ldr r7, [sp, #4] // load output pointer

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

#endif
