// can be reimplemented to use only 256 byte sbox
// precesses 256 bits of key per iteration
// 7 rounds of rcon can be computed as left shift only

// LUT loads are splitted to avoid data dependent issuing capability from even/odd DTCM words

.syntax unified
.thumb
.text
//.section .itcm.text, "x"

.align 3
// void CM7_1T_AES_256_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM7_1T_AES_256_keyschedule_enc
.type   CM7_1T_AES_256_keyschedule_enc,%function
CM7_1T_AES_256_keyschedule_enc:
#if __ARM_ARCH_7M__ || __ARM_ARCH_7EM__
	push {r4-r11, lr}

	//load key
	ldmia r1!, {r2-r9}

	movw r1, #:lower16:AES_Te2
	movt r1, #:upper16:AES_Te2
	str r1, [sp, #-8]! // put Te2 on stack before looping and reserve space on stack

	//just copy a key
	stmia r0!, {r2-r9}

	str r0, [sp, #4] //use rk later
	movs r0, #0x01 //first rcon

2:	uxtb r10, r9, ror #8
	uxtb r11, r9, ror #16
	//cannot dual issue when load offset is blocked by uxtb

	uxtb r12, r9, ror #24
	ldrb r10, [r1, r10, lsl #2] //load sbox from Te2

	uxtb r14, r9
	ldrb r11, [r1, r11, lsl #2] //load sbox from Te2

	eors r2, r0 //apply rcon
	ldrb r12, [r1, r12, lsl #2] //load sbox from Te2

	eor r2, r2, r10
	ldrb r14, [r1, r14, lsl #2] //load sbox from Te2
	//cannot use r14 in the next cycle

	eor r2, r2, r11, lsl #8
	ldr r1, [sp, #4] //replace Te2 with rk pointer

	eor r2, r2, r12, lsl #16
	lsls r0, #1

	eor r2, r2, r14, lsl #24
	str r2, [r1], #4

	eors r3, r2
	str r3, [r1], #4

	eors r4, r3
	str r4, [r1], #4

	eors r5, r4
	str r1, [sp, #4] //save rk pointer

	uxtb r10, r5, ror #16
	ldr r1, [sp] // reload Te2 // using r1 in next cycle might add penalty

	uxtb r11, r5, ror #8
	cmp r0, #0x80 //break when rcon reaches 0x80 // will use flags later

	uxtb r12, r5
	ldrb r10, [r1, r10, lsl #2] //load sbox from Te2

	uxtb r14, r5, ror #24
	ldrb r11, [r1, r11, lsl #2] //load sbox from Te2

	eor r6, r6, r10, lsl #16
	ldrb r12, [r1, r12, lsl #2] //load sbox from Te2

	eor r6, r6, r11, lsl #8
	ldrb r14, [r1, r14, lsl #2] //load sbox from Te2
	//cannot use r14 in the next cycle

	eor r6, r12
	ldr r1, [sp, #4] //replace Te2 with rk pointer

	eor r6, r6, r14, lsl #24
	str r5, [r1], #4

	itttt ne
	eorne r7, r6 // do not set a flags
	strne r6, [r1], #4

	eorne r8, r7 // do not set a flags
	strne r7, [r1], #12 // preserve space to dual issue rk saver before storing 2 last registers concatenated for single store unit

	itttt ne
	eorne r9, r8 // do not set a flags
	strne r1, [sp, #4] //save rk pointer

	strdne r8,r9, [r1, #-8] // #8

	ldrne r1, [sp] //reload Te2
	bne 2b

	add sp, #8
	pop {r4-r11, pc}
#else
	b . //crash in case the function was called on thumb1 core
#endif
