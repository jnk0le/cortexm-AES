// LUT loads are splitted to avoid data dependent issuing capability from even/odd DTCM words

.syntax unified
.thumb
.text
//.section .itcm.text, "x"

.align 3
// void CM7_1T_AES_encrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM7_1T_AES_encrypt
.type   CM7_1T_AES_encrypt,%function
CM7_1T_AES_encrypt:
	add r3, r0, r3, lsl #4 //rk_end-16 = rk + rounds * 16
	mov r12, r0

	push {r2,r3,r4-r11,lr} //stack out, rk_end-16

	movw r14, #:lower16:AES_Te0
	movt r14, #:upper16:AES_Te0

	//load input
	ldmia r1!, {r4-r7}

	//load key
	//ldmia r12!, {r0-r3}
	ldrd r0,r1, [r12], #8
	ldrd r2,r3, [r12], #8

	//initial addroundkey
	eors r4, r0
	eors r5, r1

	eors r6, r2
	eors r7, r3

	//8 + 4 alignment required here
1:	//ldmia r12!, {r8-r11}
	ldrd r8,r9, [r12], #8

	uxtb r0, r4
	ldr r10, [r12], #4

	uxtb r1, r5
	ldr r11, [r12], #4

	uxtb r2, r6
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r7
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #16
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #16
	ldr r3, [r14, r3, lsl #2]

	eor r10, r10, r2, ror #16
	eor r11, r11, r3, ror #16

	uxtb r0, r5, ror #8
	uxtb r1, r6, ror #8

	uxtb r2, r7, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r4, ror #8
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #8
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #8
	ldr r3, [r14, r3, lsl #2]

	eor r10, r10, r2, ror #8
	uxtb r0, r6, ror #16

	eor r11, r11, r3, ror #8
	uxtb r1, r7, ror #16

	uxtb r2, r4, ror #16
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r5, ror #16
	ldr r1, [r14, r1, lsl #2]

	uxtb r7, r7, ror #24
	ldr r2, [r14, r2, lsl #2]

	uxtb r4, r4, ror #24
	ldr r3, [r14, r3, lsl #2]

	uxtb r5, r5, ror #24
	ldr r7, [r14, r7, lsl #2]

	uxtb r6, r6, ror #24
	ldr r4, [r14, r4, lsl #2]

	// change xoring order to writeback r4-r7 without extra moves
	eor r0, r0, r7, ror #24
	ldr r5, [r14, r5, lsl #2]

	eor r1, r1, r4, ror #24
	ldr r6, [r14, r6, lsl #2]

	eor r2, r2, r5, ror #24
	ldr r7, [sp, #4] // assume inherited delay from register offset ldr, it works somehow on next cycle but better to avoid it

	eor r3, r3, r6, ror #24
	eor r4, r8, r0

	eor r5, r9, r1
	cmp r7, r12

	eor r6, r10, r2
	eor r7, r11, r3

	nop //
	bne 1b

	//final round
	uxtb r0, r7, ror #24
	uxtb r1, r4, ror #24

	uxtb r2, r5, ror #24
	ldr r8, [r14, r0, lsl #2]

	uxtb r3, r6, ror #24
	ldr r9, [r14, r1, lsl #2]

	uxtb r0, r6, ror #16
	ldr r10, [r14, r2, lsl #2]

	uxtb r1, r7, ror #16
	ldr r11, [r14, r3, lsl #2]

	uxtb r2, r4, ror #16
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r5, ror #16
	ldr r1, [r14, r1, lsl #2]

	bfi r8, r0, #24, #8
	ldr r2, [r14, r2, lsl #2]

	bfi r9, r1, #24, #8
	ldr r3, [r14, r3, lsl #2]

	bfi r10, r2, #24, #8
	uxtb r0, r4

	bfi r11, r3, #24, #8
	uxtb r1, r5

	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]

	uxtb r2, r6
	ldr r1, [r14, r1, lsl #2]

	bfi r8, r0, #8, #8
	ldr r2, [r14, r2, lsl #2]

	bfi r9, r1, #8, #8
	ldr r3, [r14, r3, lsl #2]

	bfi r10, r2, #8, #8
	uxtb r0, r5, ror #8

	bfi r11, r3, #8, #8
	uxtb r1, r6, ror #8

	uxtb r2, r7, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r4, ror #8
	ldr r1, [r14, r1, lsl #2]

	bfi r8, r0, #16, #8
	ldr r2, [r14, r2, lsl #2]

	bfi r9, r1, #16, #8
	ldr r3, [r14, r3, lsl #2]

	bfi r10, r2, #16, #8
	ldr r0, [r12]

	bfi r11, r3, #16, #8
	ldr r1, [r12, #4]

	eor r0, r0, r8, ror #8
	ldr r2, [r12, #8]

	eor r1, r1, r9, ror #8
	ldr r3, [r12, #12]

	eor r2, r2, r10, ror #8
	ldr r5, [sp], #8 //load output pointer and clear stack

	eor r3, r3, r11, ror #8
	ldr r4, [sp], #4 // pop early to pop even number of registers later

	stmia r5, {r0-r3}

	pop {r5-r11,pc}
