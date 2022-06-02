.syntax unified
.thumb
.text
//.section .itcm.text, "x"

.align 3
// void CM7_1T_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM7_1T_AES_encrypt
.type   CM7_1T_AES_encrypt,%function
CM7_1T_AES_encrypt:
#if __ARM_ARCH_7EM__
	//pld here at +1 cycle?
	push {r2,r4-r11,lr} //stack out

	mov r12, r0
	add r11, r0, r3, lsl #4 //rk_end-16 = rk + rounds * 16

	movw r14, #:lower16:AES_Te2
	movt r14, #:upper16:AES_Te2

	//load input
	ldmia r1!, {r4-r7}

	//load key
	ldmia r12!, {r0-r3}

	//initial addroundkey in loop

	// global allocation
	// r11 - final ptr
	// r12 - rk ptr
	// r14 - Te2

	//      s00 | s10 | s20 | s30
	//      s01 | s11 | s21 | s31
	//      s02 | s12 | s22 | s32
	//      s03 | s13 | s23 | s33

	// rotation after Te2
	// xor   16 |  8  |  0  |  24

1: // skew addroundkey to begginning of loop
	eors r0, r4
	eors r1, r5

	eors r2, r6
	eors r3, r7

	// start from col 1
	uxtb.w r5, r3, ror #16
	lsrs r4, r0, #24

	uxtb r6, r1
	ldr.w r10, [r14, r4, lsl #2]

	//current alloctaion
	// r0 -     | s10 | s20 |
	// r1 -     | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 |     | s33
	// r4 -
	// r5 - s23 // c1
	// r6 - s01 // c1 ror16
	// r7 -
	// r8 -
	// r9 -
	// r10 - s30T // c1 ror24

	lsrs r4, r3, #24
	ldr.w r5, [r14, r5, lsl #2]

	uxtb r7, r0
	ldr.w r9, [r14, r6, lsl #2]

	//current alloctaion
	// r0 -     | s10 | s20 |
	// r1 -     | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 |     |
	// r4 - s33 // c0 ror24
	// r5 - s23T // c1
	// r6 -
	// r7 - s00 // c0 ror16
	// r8 -
	// r9 - s01T // c1 ror16
	// r10 - s30T // c1 ror24

	uxtb r6, r2, ror #8
	ldr.w r8, [r14, r4, lsl #2]

	uxtb r4, r2, ror #16
	eor.w r5, r5, r10, ror #24

	//current alloctaion
	// r0 -     | s10 | s20 |
	// r1 -     | s11 | s21 | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s22 // c0
	// r5 - s23T ^ s30T // c1
	// r6 - s12 // c1 ror8
	// r7 - s00 // c0 ror16
	// r8 - s33T // c0 ror24
	// r9 - s01T // c1 ror16
	// r10 -

	eor.w r5, r5, r9, ror #16
	ldr.w r10, [r14, r7, lsl #2]

	uxtb.w r9, r1, ror #8
	ldr.w r4, [r14, r4, lsl #2]

	//current alloctaion
	// r0 -     | s10 | s20 |
	// r1 -     |     | s21 | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s22T // c0
	// r5 - s23T ^ s30T ^ s01T // c1
	// r6 - s12 // c1 ror8
	// r7 -
	// r8 - s33T // c0 ror24
	// r9 - s11 // c0 ror8
	// r10 - s00T // c0 ror16

	uxtb.w r7, r0, ror #16
	ldr.w r6, [r14, r6, lsl #2]

	eor.w r4, r4, r10, ror #16
	ldr.w r9, [r14, r9, lsl #2]

	//current alloctaion
	// r0 -     | s10 |     |
	// r1 -     |     | s21 | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s22T ^ s00T // c0
	// r5 - s23T ^ s30T ^ s01T // c1
	// r6 - s12T // c1 ror8
	// r7 - s20 // c2
	// r8 - s33T // c0 ror24
	// r9 - s11T // c0 ror8
	// r10 -

	eor.w r5, r5, r6, ror #8
	ldr.w r10, [r14, r7, lsl #2]

	uxtb.w r0, r0, ror #8
	eor.w r4, r4, r8, ror #24

	//current alloctaion
	// r0 - s10 // c3 ror8
	// r1 -     |     | s21 | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s22T ^ s00T ^ s33T // c0
	// r5 - col 1
	// r6 -
	// r7 -
	// r8 -
	// r9 - s11T // c0 ror8
	// r10 - s20T // c2

	uxtb r7, r2
	eor.w r4, r4, r9, ror #8

	lsrs r6, r1, #24
	ldr.w r9, [r14, r0, lsl #2]

	//current alloctaion
	// r0 -
	// r1 -     |     | s21 |
	// r2 -     |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - col 0
	// r5 - col 1
	// r6 - s31 // c2 ror24
	// r7 - s02 // c2 ror16
	// r8 -
	// r9 - s10T // c3 ror8
	// r10 - s20T // c2

	uxtb.w r8, r3, ror #8
	ldr.w r7, [r14, r7, lsl #2]

	uxtb.w r1, r1, ror #16
	ldr.w r6, [r14, r6, lsl #2]

	//current alloctaion
	// r0 -
	// r1 - s21 // c3
	// r2 -     |     |     | s32
	// r3 - s03 |     |     |
	// r4 - col 0
	// r5 - col 1
	// r6 - s31T // c2 ror24
	// r7 - s02T // c2 ror16
	// r8 - s13 // c2 ror8
	// r9 - s10T // c3 ror8
	// r10 - s20T // c2

	lsrs r2, #24
	ldr.w r8, [r14, r8, lsl #2]

	uxtb r3, r3
	eor.w r6, r10, r6, ror #24

	//current alloctaion
	// r0 -
	// r1 - s21 // c3
	// r2 - s32 // c3 ror24
	// r3 - s03 // c3 ror16
	// r4 - col 0
	// r5 - col 1
	// r6 - s20T ^ s31T // c2
	// r7 - s02T // c2 ror16
	// r8 - s13T // c2 ror8
	// r9 - s10T // c3 ror8
	// r10 -

	eor.w r6, r6, r7, ror #16
	ldr.w r10, [r14, r1, lsl #2]

	eor.w r6, r6, r8, ror #8
	ldr.w r7, [r14, r2, lsl #2]

	ldrd r0,r1, [r12], #16

	//current alloctaion
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 -
	// r3 - s03 // c3 ror16
	// r4 - col 0
	// r5 - col 1
	// r6 - col 2
	// r7 - s32T // c3 ror24
	// r8 -
	// r9 - s10T // c3 ror8
	// r10 - s21T // c3

	cmp r11, r12 // cmp early
	ldr.w r8, [r14, r3, lsl #2]

	eor.w r7, r10, r7, ror #24
	ldr r2, [r12, #-8]

	eor.w r7, r7, r9, ror #8
	ldr r3, [r12, #-4]

	eor.w r7, r7, r8, ror #16
	bne 1b

	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	// old final round // opt later

	uxtb r9, r2, ror #16 //row 2 col 0
	lsrs.w r7, r3, #24 //row 3 col 0

	uxtb r10, r1, ror #8 //row 1 col 0
	and r11, r0, #0xff //row 0 col 0

	lsrs.w r4, r0, #24 //row 3 col 1
	ldrb r8, [r14, r7, lsl #2]

	uxtb r5, r3, ror #16
	ldrb r9, [r14, r9, lsl #2]

	uxtb.w r6, r1 //row 0 col 1
	ldrb r10, [r14, r10, lsl #2]

	uxtb r7, r2, ror #8 //row 1 col 1
	ldrb r11, [r14, r11, lsl #2]

	orr.w r9, r9, r8, lsl #8 // column 0 upper part
	ldrb r4, [r14, r4, lsl #2]

	uxtb r8, r0, ror #16 //row 2 col 2
	ldrb r5, [r14, r5, lsl #2]

	orr.w r11, r11, r10, lsl #8 // column 0 bottom part
	ldrb r6, [r14, r6, lsl #2]

	uxtb r10, r0, ror #8 //row 1 col 3
	ldrb r7, [r14, r7, lsl #2]

	orr.w r11, r11, r9, lsl #16 // col 0
	ldr r0, [r12, #0] // column 0 is ready to eor and store

	orr.w r5, r5, r4, lsl #8 // column 1 upper part
	ldrb r8, [r14, r8, lsl #2]

	orr.w r7, r6, r7, lsl #8 //column 1 bottom part
	ldrb r10, [r14, r10, lsl #2]

	orr.w r7, r7, r5, lsl #16 //col 1
	lsrs.w r4, r1, #24 //row 3 col 2

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
	ldrb r4, [r14, r4, lsl #2]

	lsr.w r2, r2, #24 //row 3 col 3
	ldrb r6, [r14, r6, lsl #2]

	and.w r3, r3, #0xff //row 0 col 3
	ldrb r5, [r14, r5, lsl #2]

	orr.w r4, r8, r4, lsl #8 // col 2 upper part
	ldrb r9, [r14, r9, lsl #2]

	eor r0, r0, r11 // finish col 0
	ldrb r2, [r14, r2, lsl #2]

	orr.w r5, r6, r5, lsl #8 // col 2 bottom part
	ldrb r3, [r14, r3, lsl #2]

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

	eors.w r1, r7
	ldr r3, [r12, #12]

	eors.w r2, r4
	str.w r0, [r5, #0]

	orr.w r6, r10, r6, lsl #16 // finish col 3
	str.w r1, [r5, #4]

	ldr r4, [sp], #4 // pop early to pop even number of registers
	str.w r2, [r5, #8]

	eors.w r3, r6
	str.w r3, [r5, #12]

	pop {r5-r11,pc}
#else
	b . //crash in case the function was called on thumb1 core
#endif
