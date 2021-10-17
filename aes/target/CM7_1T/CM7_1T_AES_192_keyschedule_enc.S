// can be reimplemented to use only 256 byte sbox
// precesses 192 bits of key in every iteration
// 8 rounds of rcon can be computed as left shift only

// LUT loads are splitted to avoid data dependent issuing capability from even/odd DTCM words

.syntax unified
.thumb
.text
//.section .itcm.text, "x"

.align 3
// void CM7_1T_AES_192_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM7_1T_AES_192_keyschedule_enc
.type   CM7_1T_AES_192_keyschedule_enc,%function
CM7_1T_AES_192_keyschedule_enc:
#if __ARM_ARCH_7M__ || __ARM_ARCH_7EM__
	push {r4-r10, lr}

	movw r14, #:lower16:AES_Te2
	movt r14, #:upper16:AES_Te2

	//load key
	ldmia r1!, {r2-r7}
	movw r1, #0x01 //first rcon //align following code to 4 bytes

	//just copy a key
	stmia r0!, {r2-r7}

1:	uxtb r8, r7, ror #8
	uxtb r9, r7, ror #16
	//cannot dual issue when load offset is blocked by uxtb

	uxtb r10, r7, ror #24
	ldrb r8, [r14, r8, lsl #2] //load sbox from Te2

	uxtb r12, r7
	ldrb r9, [r14, r9, lsl #2] //load sbox from Te2

	eors r2, r1 //apply rcon
	ldrb r10, [r14, r10, lsl #2] //load sbox from Te2

	eor r2, r2, r8
	ldrb r12, [r14, r12, lsl #2] //load sbox from Te2
	//cannot use r12 in the next cycle

	eor r2, r2, r9, lsl #8
	lsls r1, #1

	eor r2, r2, r10, lsl #16
	cmp r1, 0x80 //break when rcon is greater than 0x80 // will use flags later

	eor r2, r2, r12, lsl #24
	str r2, [r0], #4

	eor r3, r2 // do not set a flags
	str r3, [r0], #4

	eor r4, r3 // do not set a flags
	str r4, [r0], #4

	eor r5, r4 // do not set a flags
	str r5, [r0], #4

	itttt ls  // last 2 words are ommited
	eorls r6, r5 // do not set a flags
	strls r6, [r0], #4

	eorls r7, r6 // do not set a flags
	strls r7, [r0], #4

	bls 1b

	pop {r4-r10, pc}
#else
	b . //crash in case the function was called on thumb1 core
#endif
