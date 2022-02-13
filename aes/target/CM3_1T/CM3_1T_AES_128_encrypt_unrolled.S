.include "aes/target/CM3_1T/CM3_1T_AES_common.inc"

.syntax unified
.thumb
.text

.align 3
// void CM3_1T_AES_128_encrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out) {
.global CM3_1T_AES_128_encrypt_unrolled
.type   CM3_1T_AES_128_encrypt_unrolled,%function
CM3_1T_AES_128_encrypt_unrolled:
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

	//final round
	//row 3 - ST3x
	lsrs r0, r7, #24
	lsrs r1, r4, #24
	lsrs r2, r5, #24
	lsrs r3, r6, #24

	//row 2 - ST2x
	uxtb r8, r6, ror #16
	uxtb r9, r7, ror #16
	uxtb r10, r4, ror #16
	uxtb r11, r5, ror #16

	ldrb r0, [r14, r0, lsl #2]
	ldrb r1, [r14, r1, lsl #2]
	ldrb r2, [r14, r2, lsl #2]
	ldrb r3, [r14, r3, lsl #2]

	ldrb r8, [r14, r8, lsl #2]
	ldrb r9, [r14, r9, lsl #2]
	ldrb r10, [r14, r10, lsl #2]
	ldrb r11, [r14, r11, lsl #2]

	//repack upper part (keep in bottom half)
	orr r8, r8, r0, lsl #8
	orr r9, r9, r1, lsl #8
	orr r10, r10, r2, lsl #8
	orr r11, r11, r3, lsl #8

	//row 1 - ST1x
	uxtb r0, r5, ror #8
	uxtb r1, r6, ror #8
	uxtb r2, r7, ror #8
	uxtb r3, r4, ror #8

	//row 0 - ST0x
	uxtb r4, r4
	uxtb r5, r5
	uxtb r6, r6
	uxtb r7, r7

	ldrb r0, [r14, r0, lsl #2]
	ldrb r1, [r14, r1, lsl #2]
	ldrb r2, [r14, r2, lsl #2]
	ldrb r3, [r14, r3, lsl #2]

	ldrb r4, [r14, r4, lsl #2]
	ldrb r5, [r14, r5, lsl #2]
	ldrb r6, [r14, r6, lsl #2]
	ldrb r7, [r14, r7, lsl #2]

	//repack bottom part
	orr r4, r4, r0, lsl #8
	orr r5, r5, r1, lsl #8
	orr r6, r6, r2, lsl #8
	orr r7, r7, r3, lsl #8

	//repack wholly
	orr r4, r4, r8, lsl #16
	orr r5, r5, r9, lsl #16
	orr r6, r6, r10, lsl #16
	orr r8, r7, r11, lsl #16 // unstack into r7

	ldr r7, [sp], #4 // load output pointer and clear stack
	ldr r0, [r12, #160]
	ldr r1, [r12, #164]
	ldr r2, [r12, #168]
	ldr r3, [r12, #172]

	eors r0, r4
	eors r1, r5
	eors r2, r6
	eor.w r3, r8

	str r0, [r7, #0]
	str r1, [r7, #4]
	str r2, [r7, #8]
	str r3, [r7, #12]

	pop {r4-r11,pc}
#else
	b . //crash in case the function was called on thumb1 core
#endif
