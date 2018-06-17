// can be reimplemented to use only 256 byte sbox
// precesses 256 bits of key per iteration
// 7 rounds of rcon can be computed as left shift only

.syntax unified
.thumb
.text

.align 2
// void CM34_1T_AES_256_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM34_1T_AES_256_keyschedule_enc
.type   CM34_1T_AES_256_keyschedule_enc,%function
CM34_1T_AES_256_keyschedule_enc:
	push {r4-r11, lr}

	sub sp, #8 //faster than dummy push

	//load key
	ldmia r1!, {r2-r9}

	movw r1, #:lower16:AES_Te0
	movt r1, #:upper16:AES_Te0
	str r1, [sp] //put Te0 on stack before looping
	//str r1, [sp, #-8]! // need to test

	//just copy a key
	stmia r0!, {r2-r9}
	str r0, [sp, #4] //use rk later

	movs r0, #0x01 //first rcon

2:	uxtb r10, r9, ror #8
	uxtb r11, r9, ror #16
	uxtb r12, r9, ror #24
	uxtb r14, r9

	ldrb r10, [r1, r10, lsl #2] //load sbox from Te0
	ldrb r11, [r1, r11, lsl #2] //load sbox from Te0
	ldrb r12, [r1, r12, lsl #2] //load sbox from Te0
	ldrb r14, [r1, r14, lsl #2] //load sbox from Te0

	eors r2, r0 //apply rcon
	eor r2, r2, r10
	eor r2, r2, r11, lsl #8
	eor r2, r2, r12, lsl #16
	eor r2, r2, r14, lsl #24
	eors r3, r2
	eors r4, r3
	eors r5, r4

	uxtb r10, r5, ror #16
	uxtb r11, r5, ror #8
	uxtb r12, r5
	uxtb r14, r5, ror #24

	ldrb r10, [r1, r10, lsl #2] //load sbox from Te0
	ldrb r11, [r1, r11, lsl #2] //load sbox from Te0
	ldrb r12, [r1, r12, lsl #2] //load sbox from Te0
	ldrb r14, [r1, r14, lsl #2] //load sbox from Te0
	ldr r1, [sp, #4] //replace Te0 with rk pointer

	eor r6, r6, r10, lsl #16
	eor r6, r6, r11, lsl #8
	eor r6, r12
	eor r6, r6, r14, lsl #24
	eors r7, r6
	eor r8, r7
	eor r9, r8

	lsls r0, #1
	cmp r0, #0x80 //break when rcon reaches 0x80

	ittte ne
	stmiane r1!, {r2-r9} //write full roundkey
	strne r1, [sp, #4] //rk pointer
	ldrne r1, [sp] //Te0
	stmiaeq r1!, {r2-r5} //write only 4 words at the last round
	bne 2b

	add sp, #8 // faster than dummy pops
	pop {r4-r11, pc}
