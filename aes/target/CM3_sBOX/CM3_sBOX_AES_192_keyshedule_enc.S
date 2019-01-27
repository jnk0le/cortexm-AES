// precesses 192 bits of key in every iteration
// 8 rounds of rcon can be computed as left shift only

.syntax unified
.thumb
.text

.align 3
// void CM3_sBOX_AES_192_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM3_sBOX_AES_192_keyschedule_enc
.type   CM3_sBOX_AES_192_keyschedule_enc,%function
CM3_sBOX_AES_192_keyschedule_enc:
	push {r4-r10, lr}

	movw r14, #:lower16:AES_sbox
	movt r14, #:upper16:AES_sbox

	//load key
	ldmia.w r1, {r2-r7} // align loop entry to 8 bytes
	mov.w r1, #0x01000000 // calculate rcon in highest byte to use a carry flag

	//just copy a key
	stmia.w r0!, {r2-r7} // align loop entry to 8 bytes

1:	uxtb r8, r7, ror #8
	uxtb r9, r7, ror #16
	uxtb r10, r7, ror #24
	uxtb r12, r7

	ldrb r8, [r14, r8]
	ldrb r9, [r14, r9]
	ldrb r10, [r14, r10]
	ldrb r12, [r14, r12]

	eor r2, r2, r1, lsr #24 // rcon is in highest byte
	eor r2, r2, r8
	eor r2, r2, r9, lsl #8
	eor r2, r2, r10, lsl #16
	eor r2, r2, r12, lsl #24
	eors r3, r2
	eors r4, r3
	eors r5, r4
	eors r6, r5
	eors r7, r6

	lsls r1, #1

	itet cc // we need one round with 0x80 so use carry flag
	stmiacc r0!, {r2-r7} //write full roundkey
	stmiacs r0!, {r2-r5} //write only 4 words at the last round
	bcc 1b

	pop {r4-r10, pc}
