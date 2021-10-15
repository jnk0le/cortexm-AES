// performs perform equivalent inverse cipher transformation on expanded encryption key
// decryprion will be done backwards to avoid extra stacking or redundant code

.syntax unified
.thumb
.text

.align 3
	nop // pre padding to maintain 4 byte alignment
// void CM3_1T_AES_keyschedule_dec_noTe(uint8_t* rk, size_t rounds) {
.global CM3_1T_AES_keyschedule_dec_noTe
.type   CM3_1T_AES_keyschedule_dec_noTe,%function
CM3_1T_AES_keyschedule_dec_noTe:
#if __ARM_ARCH_7M__
	push {r4-r5, lr}

	//first and last block are ommited
	//rk_end-16 = rk + rounds * 16
	add r1, r0, r1, lsl #4
	add r14, r0, #16

	movw r0, #:lower16:AES_sbox
	movt r0, #:upper16:AES_sbox
	movw r12, #:lower16:AES_Td2
	movt r12, #:upper16:AES_Td2

1:	ldr r2, [r1, #-4]!

	uxtb r3, r2
	uxtb r4, r2, ror #8
	//uxtb r5, r2, ror #24
	lsrs r5, r2, #24
	uxtb r2, r2, ror #16

	ldrb r3, [r0, r3]
	ldrb r4, [r0, r4]
	ldrb r2, [r0, r2]
	ldrb r5, [r0, r5]
	ldr r3, [r12, r3, lsl #2]
	ldr r4, [r12, r4, lsl #2]
	ldr r2, [r12, r2, lsl #2]
	ldr r5, [r12, r5, lsl #2]

	// set flags early to optimize speculative fetches in cm3
	// cmp have to be close to branch, otherwise speculative code loads doesn't work
	cmp r1, r14

	eor r2, r2, r3, ror #16
	eor r2, r2, r4, ror #8
	eor r2, r2, r5, ror #24
	str r2, [r1] // write back transformed key

	bne 1b

	pop {r4-r5, pc}
#else
	b . //crash in case the function was called on thumb1 core
#endif
