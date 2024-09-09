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

.balign 4
// void CM4_DSPsBOX_AES_decrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM4_DSPsBOX_AES_decrypt
.type   CM4_DSPsBOX_AES_decrypt,%function
CM4_DSPsBOX_AES_decrypt:
	push {r2,r4-r11,lr} // out

	add.w r11, r0, #16 // to compare against before final round
	add r12, r11, r3, lsl #4 // rk_end = rk+16 + rounds * 16

	//load input
	ldmia.w r1!, {r4-r7} // align loop entry

	//load initial round key
	ldmdb r12!, {r0-r3}

	//initial addroundkey
	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	movw r7, #:lower16:AES_inv_sbox
	movt r7, #:upper16:AES_inv_sbox

	// global allocation
	// r7 - inv_sbox
	// r11 - final
	// r12 - rk

	// r0 - s00 | s10 | s20 | s30
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33

	//final
	// r4 - s00`| s13`| s22`| s31`
	// r5 - s01`| s10`| s23`| s32`
	// r6 - s02`| s11`| s20`| s33`
	// r7 - s03`| s12`| s21`| s30`

1:	// inv shiftrows and subbytes
	uxtb r4, r0
	lsrs r6, r1, #24
	uxtb r8, r3, ror #8
	uxtb r9, r2, ror #16
	uxtb r5, r1
	uxtb r10, r0, ror #8
	uxtb r14, r3, ror #16

	ldrb r4, [r7, r4]
	ldrb r6, [r7, r6]
	ldrb r5, [r7, r5]
	ldrb.w r8, [r7, r8]
	ldrb.w r9, [r7, r9]
	ldrb.w r10, [r7, r10]
	ldrb.w r14, [r7, r14]

	//current allocation
	// r0 -  -  |  -  | s20 | s30
	// r1 -  -  | s11 | s21 |  -
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 |  -  |  -  | s33
	// r4 - s00` // c0r0
	// r5 - s01` // c1r0
	// r6 - s31` // c0r3
	// r8 - s13` // c0r1
	// r9 - s22` // c0r2
	// r10 - s10` // c1r1
	// r14 - s23` // c1r2

	orr.w r4, r4, r6, lsl #24
	orr.w r4, r4, r8, lsl #8
	orr.w r9, r4, r9, lsl #16 // keep col 0 outside lower regs
	orr.w r10, r5, r10, lsl #8
	orr.w r10, r10, r14, lsl #16

	//current allocation
	// r0 -  -  |  -  | s20 | s30
	// r1 -  -  | s11 | s21 |  -
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 |  -  |  -  | s33
	// r4 -
	// r5 -
	// r6 -
	// r8 -
	// r9 - s00`| s13`| s22`| s31`
	// r10 - s01`| s10`| s23`|
	// r14 -

	lsrs r4, r3, #24
	lsrs r5, r0, #24
	uxtb r8, r1, ror #8
	uxtb r14, r1, ror #16
	lsrs r1, r2, #24
	uxtb r3, r3
	uxtb r0, r0, ror #16
	uxtb r6, r2, ror #8
	uxtb r2, r2

	ldrb r4, [r7, r4]
	ldrb r5, [r7, r5]
	ldrb r1, [r7, r1]
	ldrb r3, [r7, r3]
	ldrb r0, [r7, r0]
	ldrb r6, [r7, r6]
	ldrb r2, [r7, r2]
	ldrb.w r8, [r7, r8]
	ldrb.w r14, [r7, r14]

	//current allocation
	// r0 - s20` // c2r2
	// r1 - s32` // c1r3
	// r2 - s02` // c2r0
	// r3 - s03` // c3r0
	// r4 - s33` // c2r3
	// r5 - s30` // c3r3
	// r6 - s12` // c3r1
	// r8 - s11` // c2r1
	// r9 - s00`| s13`| s22`| s31`
	// r10 - s01`| s10`| s23`|
	// r14 - s21` // c3r2

	orr.w r1, r10, r1, lsl #24
	orr.w r2, r2, r8, lsl #8
	orr.w r2, r2, r0, lsl #16
	orr.w r2, r2, r4, lsl #24
	orr.w r3, r3, r6, lsl #8
	orr.w r3, r3, r14, lsl #16
	orr.w r3, r3, r5, lsl #24

	//addroundkey
	ldmdb r12!, {r0,r4-r6}

	//current allocation
	// r0 - rk[0]
	// r1 - s01`| s10`| s23`| s32`
	// r2 - s02`| s11`| s20`| s33`
	// r3 - s03`| s12`| s21`| s30`
	// r4 - rk[1]
	// r5 - rk[2]
	// r6 - rk[3]
	// r8 -
	// r9 - s00`| s13`| s22`| s31`
	// r10 -
	// r14 -

	eor.w r0, r0, r9
	eors r1, r4
	eors r2, r5
	eors r3, r6

	//do invMixColumns as
	// r0 = S{1}
	// r4 = S{2}
	// r5 = S{4}
	// r6 = S{8}
	// r14 - tmp

	//perform quad gfmul in constant time

	uadd8 r4, r0, r0 // quad lsl #1
	eor r14, r4, #0x1b1b1b1b
	sel r4, r14, r4 // if uadd carried then take reduced byte

	uadd8 r5, r4, r4 // quad lsl #1
	eor r14, r5, #0x1b1b1b1b
	sel r5, r14, r5 // if uadd carried then take reduced byte

	uadd8 r6, r5, r5 // quad lsl #1
	eor r14, r6, #0x1b1b1b1b
	sel r6, r14, r6 // if uadd carried then take reduced byte

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
	eor r14, r4, #0x1b1b1b1b
	sel r4, r14, r4 // if uadd carried then take reduced byte

	uadd8 r5, r4, r4 // quad lsl #1
	eor r14, r5, #0x1b1b1b1b
	sel r5, r14, r5 // if uadd carried then take reduced byte

	uadd8 r6, r5, r5 // quad lsl #1
	eor r14, r6, #0x1b1b1b1b
	sel r6, r14, r6 // if uadd carried then take reduced byte

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
	eor r14, r4, #0x1b1b1b1b
	sel r4, r14, r4 // if uadd carried then take reduced byte

	uadd8 r5, r4, r4 // quad lsl #1
	eor r14, r5, #0x1b1b1b1b
	sel r5, r14, r5 // if uadd carried then take reduced byte

	uadd8 r6, r5, r5 // quad lsl #1
	eor r14, r6, #0x1b1b1b1b
	sel r6, r14, r6 // if uadd carried then take reduced byte

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
	eor r14, r4, #0x1b1b1b1b
	sel r4, r14, r4 // if uadd carried then take reduced byte

	uadd8 r5, r4, r4 // quad lsl #1
	eor r14, r5, #0x1b1b1b1b
	sel r5, r14, r5 // if uadd carried then take reduced byte

	uadd8 r6, r5, r5 // quad lsl #1
	eor r14, r6, #0x1b1b1b1b
	sel r6, r14, r6 // if uadd carried then take reduced byte

	eors r3, r6 // S{9}
	eors r6, r5
	eors r6, r4 // S{e}
	eors r4, r3 // S{b}
	eors r5, r3 // S{d}

	cmp r11, r12

	eor r3, r6, r3, ror #24
	eor r3, r3, r4, ror #8
	eor r3, r3, r5, ror #16

	bne.w 1b

	//final round
	uxtb r4, r0
	lsrs r6, r1, #24
	uxtb r8, r3, ror #8
	uxtb r9, r2, ror #16
	uxtb r5, r1
	uxtb r10, r0, ror #8
	uxtb r14, r3, ror #16

	ldrb r4, [r7, r4]
	ldrb r6, [r7, r6]
	ldrb r5, [r7, r5]
	ldrb.w r8, [r7, r8]
	ldrb.w r9, [r7, r9]
	ldrb.w r10, [r7, r10]
	ldrb.w r14, [r7, r14]

	//current allocation
	// r0 -  -  |  -  | s20 | s30
	// r1 -  -  | s11 | s21 |  -
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 |  -  |  -  | s33
	// r4 - s00` // c0r0
	// r5 - s01` // c1r0
	// r6 - s31` // c0r3
	// r8 - s13` // c0r1
	// r9 - s22` // c0r2
	// r10 - s10` // c1r1
	// r14 - s23` // c1r2

	orr.w r4, r4, r6, lsl #24
	orr.w r4, r4, r8, lsl #8
	orr.w r9, r4, r9, lsl #16 // keep col 0 outside lower regs
	orr.w r10, r5, r10, lsl #8
	orr.w r10, r10, r14, lsl #16

	//current allocation
	// r0 -  -  |  -  | s20 | s30
	// r1 -  -  | s11 | s21 |  -
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 |  -  |  -  | s33
	// r4 -
	// r5 -
	// r6 -
	// r8 -
	// r9 - s00`| s13`| s22`| s31`
	// r10 - s01`| s10`| s23`|
	// r14 -

	lsrs r4, r3, #24
	lsrs r5, r0, #24
	uxtb r8, r1, ror #8
	uxtb r14, r1, ror #16
	lsrs r1, r2, #24
	uxtb r3, r3
	uxtb r0, r0, ror #16
	uxtb r6, r2, ror #8
	uxtb r2, r2

	ldrb r4, [r7, r4]
	ldrb r5, [r7, r5]
	ldrb r1, [r7, r1]
	ldrb r3, [r7, r3]
	ldrb r0, [r7, r0]
	ldrb r6, [r7, r6]
	ldrb r2, [r7, r2]
	ldrb.w r8, [r7, r8]
	ldrb.w r14, [r7, r14]

	//current allocation
	// r0 - s20` // c2r2
	// r1 - s32` // c1r3
	// r2 - s02` // c2r0
	// r3 - s03` // c3r0
	// r4 - s33` // c2r3
	// r5 - s30` // c3r3
	// r6 - s12` // c3r1
	// r8 - s11` // c2r1
	// r9 - s00`| s13`| s22`| s31`
	// r10 - s01`| s10`| s23`|
	// r14 - s21` // c3r2

	orr.w r1, r10, r1, lsl #24
	orr.w r2, r2, r8, lsl #8
	orr.w r2, r2, r0, lsl #16
	orr.w r2, r2, r4, lsl #24
	orr.w r3, r3, r6, lsl #8
	orr.w r3, r3, r14, lsl #16
	orr.w r3, r3, r5, lsl #24


	//final addroudkey
	ldr r0, [r12, #-16]
	ldr r4, [r12, #-12]
	ldr r5, [r12, #-8]
	ldr r6, [r12, #-4]
	//ldmdb r12!, {r0,r4-r6}

	ldr r7, [sp], #4 // load output pointer

	//current allocation
	// r0 - rk[0]
	// r1 - s01`| s10`| s23`| s32`
	// r2 - s02`| s11`| s20`| s33`
	// r3 - s03`| s12`| s21`| s30`
	// r4 - rk[1]
	// r5 - rk[2]
	// r6 - rk[3]
	// r7 - out_p
	// r8 -
	// r9 - s00`| s13`| s22`| s31`
	// r10 -
	// r14 -

	eor.w r0, r0, r9
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
