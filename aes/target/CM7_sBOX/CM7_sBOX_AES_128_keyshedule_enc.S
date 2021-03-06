// 10 rounds of rcon can be computed as left shift + conditional reload of rcon to 0x1b after 0x80
// it can also serve as loop counter to reduce register pressure

// LUT loads are splitted to avoid data dependent issuing capability from even/odd DTCM words

.syntax unified
.thumb
.text
//.section .itcm.text, "x"

.align 3
// void CM7_sBOX_AES_128_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM7_sBOX_AES_128_keyschedule_enc
.type   CM7_sBOX_AES_128_keyschedule_enc,%function
CM7_sBOX_AES_128_keyschedule_enc:
#if __ARM_ARCH_7EM__
	push {r4-r8, lr}

	movw r14, #:lower16:AES_sbox
	movt r14, #:upper16:AES_sbox

	//load key once
	ldmia r1!, {r2-r5}
	mov.w r1, #0x01000000 // calculate rcon in highest byte to use a carry flag

	//just copy a key
	stmia r0!, {r2-r5}

1:	uxtab r6, r14, r5, ror #8
	uxtab r7, r14, r5, ror #16

	uxtb r8, r5, ror #24
	ldrb r6, [r6]

	uxtb r12, r5
	ldrb r7, [r7]

	eor r2, r2, r1, lsr #24 // rcon is in highest byte
	ldrb r8, [r14, r8]

	eors r2, r2, r6
	ldrb r12, [r14, r12]
	//cannot use r12 in the next cycle

	eor r2, r2, r7, lsl #8
	lsls r1, #1 // will use flags later

	eor r2, r2, r8, lsl #16
	it cs // we need one round with 0x80 so use carry flag
	movcs r1, #0x1b000000 // cannot do cmp next cycle

	eor r2, r2, r12, lsl #24
	str r2, [r0], #4

	eors r3, r2
	str r3, [r0], #4

	eors r4, r3
	cmp r1, #0x6c000000 // will use flags later

	eor r5, r4 // do not set a flags
	str r4, [r0], #4

	str r5, [r0], #4
	bne 1b

	pop {r4-r8, pc}
#else
	//crash in case the function was called on non dsp cortex m3
	b .
#endif
