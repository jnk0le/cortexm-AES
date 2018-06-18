.syntax unified
.thumb
.text

.align 2
// void CM34_1T_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM34_1T_AES_encrypt
.type   CM34_1T_AES_encrypt,%function
CM34_1T_AES_encrypt:
	add r3, r0, r3, lsl #4 //rk_end-16 = rk + rounds * 16
	push {r2,r3,r4-r11,lr} //stack out, rk_end-16

	movw r14, #:lower16:AES_Te0
	movt r14, #:upper16:AES_Te0

	mov r12, r0

	//load input
	ldmia r1!, {r4-r7}
	//load key
	ldmia r12!, {r0-r3}

	//initial addroundkey
	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

1:	ldmia r12!, {r8-r11}

	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	eor r8, r8, r0, ror #16
	eor r9, r9, r1, ror #16
	eor r10, r10, r2, ror #16
	eor r11, r11, r3, ror #16

	uxtb r0, r5, ror #8
	uxtb r1, r6, ror #8
	uxtb r2, r7, ror #8
	uxtb r3, r4, ror #8
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	eor r8, r8, r0, ror #8
	eor r9, r9, r1, ror #8
	eor r10, r10, r2, ror #8
	eor r11, r11, r3, ror #8

	uxtb r0, r6, ror #16
	uxtb r1, r7, ror #16
	uxtb r2, r4, ror #16
	uxtb r3, r5, ror #16
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	eor r8, r0
	eor r9, r1
	eor r10, r2
	eor r11, r3

	uxtb r0, r7, ror #24
	uxtb r1, r4, ror #24
	uxtb r2, r5, ror #24
	uxtb r3, r6, ror #24
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	eor r4, r8, r0, ror #24
	eor r5, r9, r1, ror #24
	eor r6, r10, r2, ror #24
	eor r7, r11, r3, ror #24

	ldr r0, [sp, #4]
	cmp r0, r12
	bne.w 1b //align following code to 4 bytes

	//final round
	uxtb r0, r7, ror #24
	uxtb r1, r4, ror #24
	uxtb r2, r5, ror #24
	uxtb r3, r6, ror #24
	ldr r8, [r14, r0, lsl #2]
	ldr r9, [r14, r1, lsl #2]
	ldr r10, [r14, r2, lsl #2]
	ldr r11, [r14, r3, lsl #2]

	uxtb r0, r6, ror #16
	uxtb r1, r7, ror #16
	uxtb r2, r4, ror #16
	uxtb r3, r5, ror #16
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	bfi r8, r0, #24, #8
	bfi r9, r1, #24, #8
	bfi r10, r2, #24, #8
	bfi r11, r3, #24, #8

	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	bfi r8, r0, #8, #8
	bfi r9, r1, #8, #8
	bfi r10, r2, #8, #8
	bfi r11, r3, #8, #8

	uxtb r0, r5, ror #8
	uxtb r1, r6, ror #8
	uxtb r2, r7, ror #8
	uxtb r3, r4, ror #8
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r4, [sp], #8 // load output pointer and clear stack

	bfi r8, r0, #16, #8
	bfi r9, r1, #16, #8
	bfi r10, r2, #16, #8
	bfi r11, r3, #16, #8

	ldmia r12, {r0-r3}

	eor r0, r0, r8, ror #8
	eor r1, r1, r9, ror #8
	eor r2, r2, r10, ror #8
	eor r3, r3, r11, ror #8

	str r0, [r4, #0]
	str r1, [r4, #4]
	str r2, [r4, #8]
	str r3, [r4, #12]

	pop {r4-r11,pc}
