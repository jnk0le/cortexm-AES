// can be reimplemented to use only 256 byte sbox
// precesses 256 bits of key per iteration
// 7 rounds of rcon can be computed as left shift only

.syntax unified
.thumb
.text

.align 3
// void CM34_1T_AES_256_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM34_1T_AES_256_keyschedule_enc
.type   CM34_1T_AES_256_keyschedule_enc,%function
CM34_1T_AES_256_keyschedule_enc:
	push {r4-r11, lr}

	//load key
	ldmia r1!, {r2-r9}

	movw r1, #:lower16:AES_Te0
	movt r1, #:upper16:AES_Te0
	str r1, [sp, #-8]! // put Te0 on stack before looping and reserve space on stack

	//just copy a key
	stmia r0!, {r2-r9}
	str.w r0, [sp, #4] //use rk later //align following code to 4 bytes

	mov.w r0, #0x01000000 // calculate rcon in highest byte to use a carry flag

1:	uxtb r10, r9, ror #8
	uxtb r11, r9, ror #16
	uxtb r12, r9, ror #24
	uxtb r14, r9

	ldrb r10, [r1, r10, lsl #2] //load sbox from Te0
	ldrb r11, [r1, r11, lsl #2] //load sbox from Te0
	ldrb r12, [r1, r12, lsl #2] //load sbox from Te0
	ldrb r14, [r1, r14, lsl #2] //load sbox from Te0

	eor r2, r2, r0, lsr #24 // rcon is in highest byte
	eor r2, r2, r10
	eor r2, r2, r11, lsl #8
	eor r2, r2, r12, lsl #16
	eor r2, r2, r14, lsl #24
	eors r3, r2
	eors r4, r3
	eor.w r5, r4 // align to 4 bytes

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

	lsls r0, #1 // set flags early

	ittte pl // negative flag is set when r0 = 0x80000000
	stmiapl r1!, {r2-r9} //write full roundkey
	strpl r1, [sp, #4] //rk pointer
	ldrpl r1, [sp] //Te0
	stmiami r1!, {r2-r5} //write only 4 words at the last round
	bpl 1b

	add sp, #8 // faster than dummy pops
	pop {r4-r11, pc}
