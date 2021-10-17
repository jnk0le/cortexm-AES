.include "aes/target/CM7_1T/CM7_1T_AES_common.inc"

.syntax unified
.thumb
.text
//.section .itcm.text, "x"

.align 3
// void CM7_1T_AES_256_encrypt_unrolled(uint8_t* rk, const uint8_t* in, uint8_t* out) {
.global CM7_1T_AES_256_encrypt_unrolled
.type   CM7_1T_AES_256_encrypt_unrolled,%function
CM7_1T_AES_256_encrypt_unrolled:
#if __ARM_ARCH_7M__ || __ARM_ARCH_7EM__
	pld [r1, #0] // dead cycle anyway, preload in case data is still in external mem, cacheline is 32 bytes
	mov r12, r0

	push {r2,r4-r11,lr} //stack out

	movw r14, #:lower16:AES_Te2
	movt r14, #:upper16:AES_Te2

	//load input
	ldmia r1!, {r4-r7}

	//load key
	ldmia r12!, {r0-r3}

	//initial addroundkey
	eor.w r0, r4
	eor.w r1, r5

	eor.w r2, r6
	eor.w r3, r7

	CM7_1T_unrolled_enc_round // 1
	CM7_1T_unrolled_enc_round // 2
	CM7_1T_unrolled_enc_round // 3
	CM7_1T_unrolled_enc_round // 4
	CM7_1T_unrolled_enc_round // 5
	CM7_1T_unrolled_enc_round // 6
	CM7_1T_unrolled_enc_round // 7
	CM7_1T_unrolled_enc_round // 8
	CM7_1T_unrolled_enc_round // 9
	CM7_1T_unrolled_enc_round // 10
	CM7_1T_unrolled_enc_round // 11
	CM7_1T_unrolled_enc_round // 12
	CM7_1T_unrolled_enc_round // 13

	// final round // recycled from DSPsBOX // not narrowed yet

	uxtb r9, r2, ror #16 //row 2 col 0
	lsr.w r7, r3, #24 //row 3 col 0

	uxtb r10, r1, ror #8 //row 1 col 0
	and r11, r0, #0xff //row 0 col 0

	lsr.w r4, r0, #24 //row 3 col 1
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
	ldr.w r0, [r12, #0] // column 0 is ready to eor and store // ??

	orr.w r5, r5, r4, lsl #8 // column 1 upper part
	ldrb r8, [r14, r8, lsl #2]

	orr.w r7, r6, r7, lsl #8 //column 1 bottom part
	ldrb r10, [r14, r10, lsl #2]

	orr.w r7, r7, r5, lsl #16 //col 1
	lsr.w r4, r1, #24 //row 3 col 2

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

	eor.w r1, r7
	ldr r3, [r12, #12]

	eor.w r2, r4
	str r0, [r5, #0]

	orr.w r6, r10, r6, lsl #16 // finish col 3
	str r1, [r5, #4]

	ldr r4, [sp], #4 // pop early to pop even number of registers
	str r2, [r5, #8]

	eor.w r3, r6
	str r3, [r5, #12]

	pop {r5-r11,pc}
#else
	b . //crash in case the function was called on thumb1 core
#endif
