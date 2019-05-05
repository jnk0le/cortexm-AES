// uses backward expanded round key
// LUT loads are splitted to avoid data dependent issuing capability from even/odd DTCM words

.syntax unified
.thumb
.text
//.section .itcm.text, "x"

.align 3
// void CM7_1T_AES_decrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM7_1T_AES_decrypt
.type   CM7_1T_AES_decrypt,%function
CM7_1T_AES_decrypt:
	adds r0, #16 //to compare against before final round
	str.w r14, [sp, -4]! // push lr

	add r12, r0, r3, lsl #4 //rk_end = rk+16 + rounds * 16
	str.w r11, [sp, -4]! // push r11

	push {r0, r2, r4-r10} //stack rk+16, out

	movw r14, #:lower16:AES_Td2
	movt r14, #:upper16:AES_Td2

	//load input
	ldmia r1!, {r4-r7}

	//load initial round key
	ldmdb r12!, {r0-r3}

	//initial addroundkey
	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

1:
	uxtb r8, r2, ror #16
	lsr.w r4, r1, #24

	uxtb r9, r3, ror #16
	lsr.w r5, r2, #24

	lsr.w r6, r3, #24
	ldr r4, [r14, r4, lsl #2]

	uxtb r10, r0, ror #16
	ldr r8, [r14, r8, lsl #2]

	lsr.w r7, r0, #24
	ldr r5, [r14, r5, lsl #2]

	uxtb r11, r1, ror #16
	ldr r9, [r14, r9, lsl #2]

	eor r4, r8, r4, ror #24
	ldr r6, [r14, r6, lsl #2]

	eor r5, r9, r5, ror #24
	ldr r10, [r14, r10, lsl #2]

	//cannot eor yet - so try to free up r0
	// r8 -> r4 ror16
	// r9 -> r5 ror8

	uxtb r9, r0, ror #8
	ldr r7, [r14, r7, lsl #2]

	eor r6, r10, r6, ror #24
	ldr r11, [r14, r11, lsl #2]

	uxtb r8, r0
	ldr r9, [r14, r9, lsl #2]

	eor r7, r11, r7, ror #24
	ldr r0, [r12, #-16]!

	//free up r1
	// r10 -> r5 ror16
	// r11 -> r6 ror8

	uxtb r10, r1
	ldr r8, [r14, r8, lsl #2]

	uxtb r11, r1, ror #8
	ldr r1, [r12, #4]

	eor r5, r5, r9, ror #8
	ldr r10, [r14, r10, lsl #2]

	eor r4, r4, r8, ror #16
	ldr r11, [r14, r11, lsl #2]

	// now r2
	// r8 -> r6 ror16
	// r9 -> r7 ror8

	uxtb r8, r2
	eor r5, r5, r10, ror #16

	uxtb r9, r2, ror #8
	ldr r2, [r12, #8]

	eor r6, r6, r11, ror #8
	ldr r8, [r14, r8, lsl #2]

	// r3
	// r10 -> r7 ror16
	// r11 -> r0 ror8

	uxtb r10, r3
	ldr r9, [r14, r9, lsl #2]

	uxtb r11, r3, ror #8
	ldr r3, [r12, #12]

	eor r6, r6, r8, ror #16
	ldr.w r8, [sp, #0]

	eor r7, r7, r9, ror #8
	ldr r10, [r14, r10, lsl #2]

	cmp.w r8, r12 // cmp at least 3 cycles before branch
	ldr r11, [r14, r11, lsl #2]

	eor r7, r7, r10, ror #16
	eor.w r0, r4

	eor r0, r0, r11, ror #8
	eor.w r1, r5

	eor.w r2, r6
	eor.w r3, r7

	nop.w // cannot dual issue anything after branch // cannot use it block above to increment stack
	bne.w 1b

	movw r14, #:lower16:AES_inv_sbox
	movt r14, #:upper16:AES_inv_sbox

	uxtb r4, r2, ror #16 // row 2 col 0 // cant uxtab
	lsr.w r5, r1, #24 // row 3 col 0 // cant .n

	//one extra cycle before ldr offsets are available

	uxtb r6, r3, ror #8 // row 1 col 0 // cant uxtab
	and.w r7, r0, #0xff // row 0 col 0

	lsr.w r8, r2, #24 //row 3 col 1
	ldrb r5, [r14, r5]

	uxtb r9, r3, ror #16 // row 2 col 1
	ldrb r4, [r14, r4]

	uxtb r10, r0, ror #8 // row 1 col 1
	ldrb r6, [r14, r6]

	uxtb r11, r1 // row 0 col 1
	ldrb r7, [r14, r7]

	orr.w r4, r4, r5, lsl #8  //column 0 upper part
	ldrb r8, [r14, r8]

	// clear r0 first

	uxtb r5, r0, ror #24 // row 3 col 3
	ldrb r9, [r14, r9]

	orr.w r6, r7, r6, lsl #8 // column 0 bottom part
	ldrb r10, [r14, r10]

	uxtab r7, r14, r0, ror #16 // row 2 col 2
	ldrb r11, [r14, r11]

	//current allocation
	// r0 -
	// r1 - old col 1
	// r2 - old col 2
	// r3 - old col 3
	// r4 - col 0 upper
	// r5 - row 3 col 3
	// r6 - col 0 bottom
	// r7 - row 2 col 2
	// r8 - row 3 col 1
	// r9 - row 2 col 1
	// r10 - row 1 col 1
	// r11 - row 0 col 1

	orr.w r4, r6, r4, lsl #16 // col 0
	ldrb r5, [r14, r5]

	//clear r1

	uxtb r6, r1, ror #8 // row 1 col 2 // cannot uxtab
	orr.w r8, r9, r8, lsl #8 // col 1 upper part

	uxtb r9, r1, ror #16 // row 2 col 3
	orr.w r10, r11, r10, lsl #8 // col 1 bottom part

	//current allocation
	// r0 -
	// r1 -
	// r2 - old col 2
	// r3 - old col 3
	// r4 - col 0
	// r5 - row 3 col 3
	// r6 - row 1 col 2
	// r7 - row 2 col 2
	// r8 - col 1 upper
	// r9 - row 2 col 3
	// r10 - col 1 bottom
	// r11 -

	//clear r2

	uxtb r11, r2, ror #8 // row 1 col 3
	ldrb r7, [r7]

	orr.w r8, r10, r8, lsl #16 // col 1
	ldrb r9, [r14, r9]

	uxtb r10, r2 // row 0 col 2
	ldrb r6, [r14, r6]

	//current allocation
	// r0 -
	// r1 -
	// r2 -
	// r3 - old col 3
	// r4 - col 0
	// r5 - row 3 col 3
	// r6 - row 1 col 2
	// r7 - row 2 col 2
	// r8 - col 1
	// r9 - row 2 col 3
	// r10 - row 0 col 2
	// r11 - row 1 col 3

	// clear r3

	uxtb r2, r3 //row 0 col 3
	ldrb r11, [r14, r11]

	lsrs r1, r3, #24 // row 3 col 2
	ldrb r10, [r14, r10]

	orr.w r5, r9, r5, lsl #8 // col 3 upper part
	ldrb r9, [r14, r2]

	//current allocation
	// r0 -
	// r1 - row 3 col 2
	// r2 -
	// r3 -
	// r4 - col 0
	// r5 - col 3 upper
	// r6 - row 1 col 2
	// r7 - row 2 col 2
	// r8 - col 1
	// r9 - row 0 col 3
	// r10 - row 0 col 2
	// r11 - row 1 col 3

	orr.w r10, r10, r6, lsl #8 // col 2 bottom part
	ldrb r6, [r14, r1]

	//current allocation
	// r0 -
	// r1 -
	// r2 -
	// r3 -
	// r4 - col 0
	// r5 - col 3 upper
	// r6 - row 3 col 2
	// r7 - row 2 col 2
	// r8 - col 1
	// r9 - row 0 col 3
	// r10 - col 2 bottom
	// r11 - row 1 col 3

	eor.w r11, r9, r11, lsl #8 // col 3 bottom
	ldr r0, [r12, #-16]!

	eor.w r5, r11, r5, lsl #16 // col 3
	ldr r1, [r12, #4]

	add sp, #4 // clear stack
	ldr r2, [r12, #8]

	orr.w r7, r7, r6, lsl #8 // col 2 upper
	ldr r3, [r12, #12]

	//current allocation
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 - col 0
	// r5 - col 3
	// r6 -
	// r7 - col 2 upper
	// r8 - col 1
	// r9 -
	// r10 - col 2 bottom
	// r11 -

	nop // half cycle is lost anyway
	ldr r6, [sp], #4 //load output pointer and clear stack

	eors r0, r4
	eor r1, r8

	orr.w r7, r10, r7, lsl #16 // col2
	ldr r4, [sp], #4 // pop early to pop even number of registers later

	eors r2, r7
	eors r3, r5

	stmia r6!, {r0-r3}

	pop {r5-r11, pc}
