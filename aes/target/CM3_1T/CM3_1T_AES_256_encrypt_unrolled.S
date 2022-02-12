.include "aes/target/CM3_1T/CM3_1T_AES_common.inc"

.syntax unified
.thumb
.text

.align 3
// void CM3_1T_AES_256_encrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out) {
.global CM3_1T_AES_256_encrypt_unrolled
.type   CM3_1T_AES_256_encrypt_unrolled,%function
CM3_1T_AES_256_encrypt_unrolled:
#if __ARM_ARCH_7M__ || __ARM_ARCH_7EM__
	push {r2,r4-r11,lr} // stack output pointer

	mov.w r12, r0 // align following code to 4 bytes

	movw r14, #:lower16:AES_Te2
	movt r14, #:upper16:AES_Te2

	//load input
	//ldmia r1!, {r4-r7}
	ldr r4, [r1, #0]
	ldr r5, [r1, #4]
	ldr r6, [r1, #8]
	ldr r7, [r1, #12]

	//load key
	//ldmia r12!, {r0-r3}
	ldr r0, [r12, #0]
	ldr r1, [r12, #4]
	ldr r2, [r12, #8]
	ldr r3, [r12, #12]

	//initial addroundkey
	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	CM3_1T_unrolled_enc_round_n 1
	CM3_1T_unrolled_enc_round_n 2
	CM3_1T_unrolled_enc_round_n 3
	CM3_1T_unrolled_enc_round_n 4
	CM3_1T_unrolled_enc_round_n 5
	CM3_1T_unrolled_enc_round_n 6
	CM3_1T_unrolled_enc_round_n 7
	CM3_1T_unrolled_enc_round_n 8
	CM3_1T_unrolled_enc_round_n 9
	CM3_1T_unrolled_enc_round_n 10
	CM3_1T_unrolled_enc_round_n 11
	CM3_1T_unrolled_enc_round_n 12
	CM3_1T_unrolled_enc_round_n 13

	//final round
	uxtb r8, r7, ror #24
	uxtb r9, r4, ror #24
	uxtb r10, r5, ror #24
	uxtb r11, r6, ror #24

	uxtb r0, r6, ror #16
	uxtb r1, r7, ror #16
	uxtb r2, r4, ror #16
	uxtb r3, r5, ror #16

	ldrb r8, [r14, r8, lsl #2]
	ldrb r9, [r14, r9, lsl #2]
	ldrb r10, [r14, r10, lsl #2]
	ldrb r11, [r14, r11, lsl #2]

	ldrb r0, [r14, r0, lsl #2]
	ldrb r1, [r14, r1, lsl #2]
	ldrb r2, [r14, r2, lsl #2]
	ldrb r3, [r14, r3, lsl #2]

	bfi r8, r0, #24, #8
	bfi r9, r1, #24, #8
	bfi r10, r2, #24, #8
	bfi r11, r3, #24, #8

	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldrb r0, [r14, r0, lsl #2]
	ldrb r1, [r14, r1, lsl #2]
	ldrb r2, [r14, r2, lsl #2]
	ldrb r3, [r14, r3, lsl #2]
	bfi r8, r0, #8, #8
	bfi r9, r1, #8, #8
	bfi r10, r2, #8, #8
	bfi r11, r3, #8, #8

	uxtb r0, r5, ror #8
	uxtb r1, r6, ror #8
	uxtb r2, r7, ror #8
	uxtb r3, r4, ror #8

	ldr r4, [sp], #4 // load output pointer and clear stack
	ldrb r0, [r14, r0, lsl #2]
	ldrb r1, [r14, r1, lsl #2]
	ldrb r2, [r14, r2, lsl #2]
	ldrb r3, [r14, r3, lsl #2]
	ldr r14, [r12, #224]
	ldr r5, [r12, #228]
	ldr r6, [r12, #232]
	ldr r7, [r12, #236]

	bfi r8, r0, #16, #8
	bfi r9, r1, #16, #8
	bfi r10, r2, #16, #8
	bfi r11, r3, #16, #8

	eor r0, r14, r8, ror #8
	eor r1, r5, r9, ror #8
	eor r2, r6, r10, ror #8
	eor r3, r7, r11, ror #8

	str r0, [r4, #0]
	str r1, [r4, #4]
	str r2, [r4, #8]
	str r3, [r4, #12]

	pop {r4-r11,pc}
#else
	b . //crash in case the function was called on thumb1 core
#endif
