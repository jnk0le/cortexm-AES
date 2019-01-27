// 10 rounds of rcon can be computed as left shift + conditional reload of rcon to 0x1b after 0x80
// it can also serve as loop counter to reduce register pressure

.syntax unified
.thumb
.text

.align 3
// void CM3_sBOX_AES_128_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM3_sBOX_AES_128_keyschedule_enc
.type   CM3_sBOX_AES_128_keyschedule_enc,%function
CM3_sBOX_AES_128_keyschedule_enc:
	push {r4-r8, lr}

	movw r14, #:lower16:AES_sbox
	movt r14, #:upper16:AES_sbox

	//load key once
	ldmia.w r1, {r2-r5} // align loop entry to 8 bytes
	mov.w r1, #0x01000000 // calculate rcon in highest byte to use a carry flag

	//just copy a key
	stmia.w r0!, {r2-r5} // align loop entry to 8 bytes

1:	uxtb r6, r5, ror #8
	uxtb r7, r5, ror #16
	uxtb r8, r5, ror #24
	uxtb r12, r5

	ldrb r6, [r14, r6]
	ldrb r7, [r14, r7]
	ldrb r8, [r14, r8]
	ldrb r12, [r14, r12]

	eor r2, r2, r1, lsr #24 // rcon is in highest byte
	eors r2, r2, r6
	eor r2, r2, r7, lsl #8
	eor r2, r2, r8, lsl #16
	eor r2, r2, r12, lsl #24
	eors r3, r2
	eors r4, r3
	eors r5, r4

	lsls r1, #1

	it cs // we need one round with 0x80 so use carry flag
	movcs r1, #0x1b000000 // cannot do cmp next cycle

	cmp r1, #0x6c000000

	//write roundkey
	stmia r0!, {r2-r5}

	bne 1b

	pop {r4-r8, pc}
