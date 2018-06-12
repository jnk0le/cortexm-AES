// can be reimplemented to use only 256 byte sbox
// precesses 192 bits of key in every iteration
// 8 rounds of rcon can be computed as left shift only

.syntax unified
.thumb
.text

.align 2
// void AES_192_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global AES_192_keyschedule_enc
.type   AES_192_keyschedule_enc,%function
AES_192_keyschedule_enc:
	push {r4-r10, lr}

	movw r14, #:lower16:AES_Te0
	movt r14, #:upper16:AES_Te0

	//load key
	ldmia r1!, {r2-r7} //align following code to 4 bytes
	movw r1, #0x01 //first rcon //align following code to 4 bytes

	//just copy a key
	stmia r0!, {r2-r7}

1:	uxtb r8, r7, ror #8
	uxtb r9, r7, ror #16
	uxtb r10, r7, ror #24
	uxtb r12, r7

	ldrb r8, [r14, r8, lsl #2] //load sbox from Te0
	ldrb r9, [r14, r9, lsl #2] //load sbox from Te0
	ldrb r10, [r14, r10, lsl #2] //load sbox from Te0
	ldrb r12, [r14, r12, lsl #2] //load sbox from Te0

	eors r2, r1 //apply rcon
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
	cmp r1, 0x80 //break when rcon is greater than 0x80

	itet ls
	stmials r0!, {r2-r7} //write full roundkey
	stmiahi r0!, {r2-r5} //write only 4 words at the last round
	bls 1b

	pop {r4-r10, pc}
