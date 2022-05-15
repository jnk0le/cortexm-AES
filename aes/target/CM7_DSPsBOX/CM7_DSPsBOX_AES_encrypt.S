/*!
 * \file CM7_DSPsBOX_AES_encrypt.S
 * \brief
 *
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date Feb 2019
 */

.syntax unified
.thumb
.text

.align 3
// void CM7_DSPsBOX_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM7_DSPsBOX_AES_encrypt
.type   CM7_DSPsBOX_AES_encrypt,%function
CM7_DSPsBOX_AES_encrypt:
#if __ARM_ARCH_7EM__
	//pld here at +1 cycle?
	push {r2,r4-r11,lr} //stack out

	mov r12, r0
	add r11, r0, r3, lsl #4 //rk_end-16 = rk + rounds * 16

	movw r14, #:lower16:AES_sbox
	movt r14, #:upper16:AES_sbox

	//load input
	ldmia r1!, {r4-r7}
	//load key
	ldmia.w r12!, {r0-r3}

	//initial addroundkey in loop

	// global allocation
	// r11 - final ptr
	// r12 - rk ptr
	// r14 - sbox

	/* do mixcolumns as
	eor tmp1, r0, r0, ror #8 // tmp1 = s0^s1 | s1^s2 | s2^s3 | s3^s0
	eor r0, tmp1, r0, ror #16 // r0 = s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3

	uadd8 tmp2, tmp1, tmp1 // quad lsl #1
	eor tmp3, tmp2, #0x1b1b1b1b
	sel tmp4, tmp3, tmp2 // if uadd carried then take reduced byte

	eor r0, tmp4, r0, ror #8 // effective r0 = s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2
	eor r0, r0, rk[n] // and final addroundkey

	alternatively
	eor r0, rk[n], r0, ror #8 // effective r0 = s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2
	eor r0, r0, tmp4
	*/

1:	// skew addroundkey to begginning of loop
	eors r0, r4
	eors r3, r7

	eors r2, r6
	lsrs r7, r0, #24 // row 3 col 1

	// prepare column 1 asap
	uxtab.w r6, r14, r3, ror #16 // row 2 col 1
	eors r1, r5

	uxtab.w r5, r14, r2, ror #8 // row 1 col 1
	ldrb.w r10, [r14, r7]

	uxtb r4, r1 // row 0 col 1
	ldrb r6, [r6]

	uxtab.w r7, r14, r2, ror #16 // row 2 col 0
	ldrb r5, [r5]

	//current alloctaion
	// r0 - s00 | s10 | s20 |
	// r1 -     | s11 | s21 | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     | s33
	// r4 - s01  //r0c1
	// r5 - s12` //r1c1
	// r6 - s23` //r2c1
	// r7 - s22  //r2c0
	// r8 -
	// r9 -
	// r10 - s30` //r3c1

	orr.w r9, r6, r10, lsl #8 // col 1 upper part
	ldrb.w r4, [r14, r4]

	lsrs r6, r3, #24 // row 3 col 0
	ldrb r7, [r7]

	//current alloctaion
	// r0 - s00 | s10 | s20 |
	// r1 -     | s11 | s21 | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s01` //r0c1
	// r5 - s12` //r1c1
	// r6 - s33  //r3c0
	// r7 - s22` //r2c0
	// r8 -
	// r9 - s23` | s30` //c1 upper
	// r10 -

	orr.w r10, r4, r5, lsl #8 //c1 bottom
	ldrb.w r8, [r14, r6]

	uxtab.w r6, r14, r1, ror #8 // row 1 col 0
	lsrs r5, r1, #24 // row 3 col 2

	//current alloctaion
	// r0 - s00 | s10 | s20 |
	// r1 -     |     | s21 |
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 -
	// r5 - s31  //r3c2
	// r6 - s11  //r1c0
	// r7 - s22` //r2c0
	// r8 - s33` //r3c0
	// r9 - s23` | s30` //c1 upper
	// r10 - s01` | s12` //c1 bottom

	uxtb r4, r0 // row 0 col 0
	orr.w r10, r10, r9, lsl #16 // col 1

	orr.w r8, r7, r8, lsl #8 // col 0 upper
	ldrb.w r6, [r6]	// alignment??

	uxtab.w r7, r14, r0, ror #16 // row 2 col 2
	ldrb.w r9, [r14, r4]

	//current alloctaion
	// r0 -     | s10 |     |
	// r1 -     |     | s21 |
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 -
	// r5 - s31  //r3c2
	// r6 - s11` //r1c0
	// r7 - s20  //r2c2
	// r8 - s22` | s33` //c0 upper
	// r9 - s00` //r0c0
	// r10 - col 1

	uxtab.w r4, r14, r3, ror #8 // row 1 col 2
	ldrb.w r5, [r14, r5]

	orr.w r9, r9, r6, lsl #8 // col 0 bottom
	ldrb r7, [r7]

	//current alloctaion
	// r0 -     | s10 |     |
	// r1 -     |     | s21 |
	// r2 - s02 |     |     | s32
	// r3 - s03 |     |     |
	// r4 - s13  //r1c2
	// r5 - s31` //r3c2
	// r6 -
	// r7 - s20` //r2c2
	// r8 - s22` | s33` //c0 upper
	// r9 - s00` | s11` //c0 bottom
	// r10 - col 1

	uxtb r6, r2 // row 0 col 2
	orr.w r9, r9, r8, lsl #16 // col 0

	eor.w r8, r10, r10, ror #8 // start col 1 mixcolumn
	ldrb r4, [r4]

	orr.w r5, r7, r5, lsl #8 // col 2 upper
	ldrb.w r6, [r14, r6]

	//current alloctaion
	// r0 -     | s10 |     |
	// r1 -     |     | s21 |
	// r2 -     |     |     | s32
	// r3 - s03 |     |     |
	// r4 - s13` //r1c2
	// r5 - s20` | s31` //c2 upper
	// r6 - s02` //r0c2
	// r7 -
	// r8 - col 1 (tmp1) - s0^s1 | s1^s2 | s2^s3 | s3^s0
	// r9 - col 0
	// r10 - col 1

	eor.w r10, r8, r10, ror #16
	lsrs r2, r2, #24 // row 3 col 3

	uxtb.w r1, r1, ror #16 // row 2 col 3 // cant uxtab with inline shift
	orr.w r6, r6, r4, lsl #8 // col 2 bottom

	uxtab.w r7, r14, r0, ror #8 // row 1 col 3
	ldrb.w r2, [r14, r2]

	//current alloctaion
	// r0 -
	// r1 - s21  //r2c3
	// r2 - s32` //r3c3
	// r3 - s03 |     |     |
	// r4 -
	// r5 - s20` | s31` //c2 upper
	// r6 - s02` | s13` //c2 bottom
	// r7 - s10 //r1c3
	// r8 - col 1 (tmp1) - s0^s1 | s1^s2 | s2^s3 | s3^s0
	// r9 - col 0
	// r10 - col 1 - s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3

	uxtb r3, r3
	//and.w r3, r3, #0xff
	ldrb.w r1, [r14, r1]

	uadd8 r8, r8, r8 // quad lsl #1
	orr.w r6, r6, r5, lsl #16 // col 2

	//current alloctaion
	// r0 -
	// r1 - s21` //r2c3
	// r2 - s32` //r3c3
	// r3 - s03  //r0c3
	// r4 -
	// r5 -
	// r6 - col 2
	// r7 - s10 //r1c3
	// r8 - col 1 (tmp2)
	// r9 - col 0
	// r10 - col 1 - s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3

	eor.w r4, r8, #0x1b1b1b1b
	orr.w r5, r1, r2, lsl #8 // col 3 upper

	sel r1, r4, r8 // if uadd carried then take reduced byte
	eor.w r8, r9, r9, ror #8 // start col 0 mixcolumn

	//current alloctaion
	// r0 -
	// r1 - col 1 (tmp4)
	// r2 -
	// r3 - s03  //r0c3
	// r4 -
	// r5 - s21` | s32` //c3 upper
	// r6 - col 2
	// r7 - s10  //r1c3
	// r8 - col 0 (tmp1) - s0^s1 | s1^s2 | s2^s3 | s3^s0
	// r9 - col 0
	// r10 - col 1 - s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3

	eor.w r9, r8, r9, ror #16
	ldrb r7, [r7]

	eor.w r1, r1, r10, ror #8 // effective r10 - s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2
	ldrb.w r3, [r14, r3]

	//current alloctaion
	// r0 -
	// r1 - col 1 mixed
	// r2 -
	// r3 - s03` //r0c3
	// r4 -
	// r5 - s21` | s32` //c3 upper
	// r6 - col 2
	// r7 - s10` //r1c3
	// r8 - col 0 (tmp1) - s0^s1 | s1^s2 | s2^s3 | s3^s0
	// r9 - col 0 - s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3
	// r10 -

	uadd8 r0, r8, r8 // quad lsl #1
	eor.w r4, r6, r6, ror #8 // start col 2 mixcolumn

	eor.w r10, r0, #0x1b1b1b1b
	orr.w r7, r3, r7, lsl #8 // col 3 bottom

	sel r0, r10, r0 // if uadd carried then take reduced byte
	eor.w r10, r4, r6, ror #16

	//current alloctaion
	// r0 - col 0 (tmp4)
	// r1 - col 1 mixed
	// r2 -
	// r3 -
	// r4 - col 2 (tmp1) - s0^s1 | s1^s2 | s2^s3 | s3^s0
	// r5 - s21` | s32` //c3 upper
	// r6 -
	// r7 - s03` | s10` //c3 bottom
	// r8 -
	// r9 - col 0 - s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3
	// r10 - col 2 - s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3

	uadd8 r2, r4, r4 // quad lsl #1
	orr.w r3, r7, r5, lsl #16 // col 3

	eor.w r8, r2, #0x1b1b1b1b
	eor.w r0, r0, r9, ror #8 // effective r9 - s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	sel r2, r8, r2 // if uadd carried then take reduced byte
	eor.w r8, r3, r3, ror #8 // start col 3 mixcolumn

	ldmia r12!, {r4,r5,r6,r7}

	//current alloctaion
	// r0 - col 0 mixed
	// r1 - col 1 mixed
	// r2 - col 2 (tmp4)
	// r3 - col 3
	// r4 - rk[0]
	// r5 - rk[1]
	// r6 - rk[2]
	// r7 - rk[3]
	// r8 - col 3 (tmp1) - s0^s1 | s1^s2 | s2^s3 | s3^s0
	// r9 -
	// r10 - col 2 - s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3

	eor.w r3, r8, r3, ror #16
	cmp.w r12, r11 // cmp early

	uadd8 r8, r8, r8 // quad lsl #1
	eor.w r2, r2, r10, ror8 // effective r10 = s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	eor.w r10, r8, #0x1b1b1b1b
	eor.w r3, r7, r3, ror #8 // effective r3 - s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2 // consume rk, alt representation

	sel r7, r10, r8 // if uadd carried then take reduced byte // make loop addroundkey identical to initial add roundkey
	bne.w 1b

	// opt later
	eor.w r0, r4
	eor.w r1, r5

	eor.w r2, r6
	eor.w r3, r7

	//final round
	uxtb r9, r2, ror #16 //row 2 col 0
	lsr.w r7, r3, #24 //row 3 col 0 // cannot use .n opcode

	uxtb r10, r1, ror #8 //row 1 col 0
	and r11, r0, #0xff //row 0 col 0

	lsrs r4, r0, #24 //row 3 col 1
	ldrb r8, [r14, r7]

	uxtab r5, r14, r3, ror #16
	ldrb r9, [r14, r9]

	uxtb r6, r1 //row 0 col 1
	ldrb r10, [r14, r10]

	uxtb r7, r2, ror #8 //row 1 col 1 // cant uxtab and .n load
	ldrb r11, [r14, r11]

	orr.w r9, r9, r8, lsl #8 // column 0 upper part
	ldrb r4, [r14, r4]

	uxtb r8, r0, ror #16 //row 2 col 2
	ldrb r5, [r5]

	orr.w r11, r11, r10, lsl #8 // column 0 bottom part
	ldrb r6, [r14, r6]

	uxtb r10, r0, ror #8 //row 1 col 3
	ldrb r7, [r14, r7]

	orr.w r11, r11, r9, lsl #16 // col 0
	ldr r0, [r12, #0] // column 0 is ready to eor and store

	orr.w r5, r5, r4, lsl #8 // column 1 upper part
	ldrb r8, [r14, r8]

	orr.w r7, r6, r7, lsl #8 //column 1 bottom part
	ldrb r10, [r14, r10]

	orr.w r7, r7, r5, lsl #16 //col 1
	lsrs r4, r1, #24 //row 3 col 2

	uxtb r5, r3, ror #8 //row 1 col 2
	and.w r6, r2, 0xff //row 0 col 2

	//current allocation
	// r0 - rk[0]
	// r1 - old col 1
	// r2 - old col 2
	// r3 - old col 3
	// r4 - (row 3 col 2)
	// r5 - (row 1 col 2)
	// r6 - (row 0 col 2)
	// r7 - col 1
	// r8 - row 2 col 2
	// r9 -
	// r10 - row 1 col 3
	// r11 - col 0

	uxtb r9, r1, ror #16 //row 2 col 3
	ldrb r4, [r14, r4]

	lsr.w r2, r2, #24 //row 3 col 3 // cant .n
	ldrb r6, [r14, r6]

	and.w r3, r3, #0xff //row 0 col 3 // cant .n
	ldrb r5, [r14, r5]

	orr.w r4, r8, r4, lsl #8 // col 2 upper part
	ldrb r9, [r14, r9]

	eor r0, r0, r11 // finish col 0
	ldrb r2, [r14, r2]

	orr.w r5, r6, r5, lsl #8 // col 2 bottom part
	ldrb r3, [r14, r3]

	orr.w r4, r5, r4, lsl #16 // col 2
	ldr r1, [r12, #4] // rk[1]

	//current allocation
	// r0 - finished col 0
	// r1 - rk[1]
	// r2 - row 3 col 3  -> rk[2]
	// r3 - row 0 col 3
	// r4 - col 2
	// r5 -              -> output p
	// r6 -              -> col 3 upper
	// r7 - col 1
	// r8 -
	// r9 - row 2 col 3  ->
	// r10 - row 1 col 3 -> col 3 bottom
	// r11 -

	orr.w r6, r9, r2, lsl #8 //col 3 upper part
	ldr r5, [sp], #4 // load output pointer and clear stack

	orr.w r10, r3, r10, lsl #8 // col 3 bottom part
	ldr r2, [r12, #8] // rk[2]

	eors r1, r7
	ldr r3, [r12, #12]

	eors r2, r4
	str r0, [r5, #0]

	orr.w r6, r10, r6, lsl #16 // finish col 3
	str r1, [r5, #4]

	ldr r4, [sp], #4 // pop early to pop even number of registers
	str r2, [r5, #8]

	eors r3, r6
	str r3, [r5, #12]

	pop {r5-r11,pc}
#else
	b . //crash in case the function was called on non dsp core
#endif
