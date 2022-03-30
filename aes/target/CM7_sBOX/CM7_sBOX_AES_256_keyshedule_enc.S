// precesses 256 bits of key per iteration
// 7 rounds of rcon can be computed as left shift only

.syntax unified
.thumb
.text
//.section .itcm.text, "x"

.align 3
// void CM7_sBOX_AES_256_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM7_sBOX_AES_256_keyschedule_enc
.type   CM7_sBOX_AES_256_keyschedule_enc,%function
CM7_sBOX_AES_256_keyschedule_enc:
#if __ARM_ARCH_7EM__
	push {r4-r11, lr}

	//load key
	ldmia.w r1!, {r2-r9}

	movw r14, #:lower16:AES_sbox
	movt r14, #:upper16:AES_sbox

	mov.w r1, #0x01000000 // calculate rcon in highest byte to use negative flag

	//just copy a key
	stmia.w r0!, {r2-r5} // upper part is stored in first half of the loop

1:	uxtb r10, r9, ror #8
	and.w r11, r9, #0xff

	uxtb.w r12, r9, ror #16
	str.w r6, [r0], #4

	nop.w // cant .n
	ldrb r10, [r14, r10] // load sbox

	eor.w r2, r2, r1, lsr #24 // rcon is in highest byte
	ldrb r11, [r14, r11] // load sbox

	eor.w r2, r10
	ldrb r12, [r14, r12] // load sbox

	lsr.w r10, r9, #24 // early alu can be consumed by load next cycle
	str.w r7, [r0], #4

	eor.w r2, r2, r11, lsl #24
	ldrb r10, [r14, r10] // load sbox

	eor.w r2, r2, r12, lsl #8
	lsls r1, #1

	eor.w r3, r2 // start now, there is bubble anyway
	str.w r8, [r0], #4

	eor.w r3, r3, r10, lsl #16
	str.w r9, [r0], #4

	eor.w r4, r3
	eor.w r2, r2, r10, lsl #16 // finish r2

	eor.w r5, r4
	bmi 2f

	uxtb r10, r5, ror #8
	and.w r11, r5, #0xff

	uxtb.w r12, r5, ror #16
	str.w r2, [r0], #4

	nop
	ldrb r11, [r14, r11] // load sbox

	nop
	ldrb r10, [r14, r10] // load sbox

	eor.w r6, r11
	ldrb r12, [r14, r12] // load sbox

	lsr.w r11, r5, #24 // early alu can be consumed by load next cycle
	str.w r3, [r0], #4

	eor.w r6, r6, r10, lsl #8
	ldrb r11, [r14, r11] // load sbox

	eor.w r6, r6, r12, lsl #16
	str.w r4, [r0], #4

	eors r7, r6  // start now, there is bubble anyway
	str.w r5, [r0], #4

	eor.w r7, r7, r11, lsl #24
	nop

	eor.w r8, r7
	eor.w r6, r6, r11, lsl #24 // finish r6

	eor.w r9, r8
	b 1b

2:
	stmia r0!, {r2-r5}
	pop {r4-r11, pc}
#else
	b . //crash in case the function was called on thumb1 core
#endif
