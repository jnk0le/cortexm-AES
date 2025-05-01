/*!
 * \file CM3_1T_AES_keyschedule_dec_noTe.S
 * \brief cortex-m3/4 optimized aes decryption keyschedule
 *
 * performs equivalent inverse cipher transformation on expanded encryption key
 * order of round keys is not inverted - decryption will read it in reverse
 *
 * utilizes sbox and Td2 tables
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only
#if __ARM_EABI__ && __thumb2__

.syntax unified
.thumb
.text

.balign 4
// void CM3_1T_AES_keyschedule_dec_noTe(uint8_t* rk, size_t rounds) {
.global CM3_1T_AES_keyschedule_dec_noTe
.type   CM3_1T_AES_keyschedule_dec_noTe,%function
CM3_1T_AES_keyschedule_dec_noTe:
	push.w {r4-r5, lr} // align loop entry

	//first and last block are ommited
	//rk_end-16 = rk + rounds * 16
	add r1, r0, r1, lsl #4
	add r14, r0, #16

	movw r0, #:lower16:AES_sbox
	movt r0, #:upper16:AES_sbox
	movw r12, #:lower16:AES_Td2
	movt r12, #:upper16:AES_Td2

1:	ldr r2, [r1, #-4]! // can also go forward but requires negative offset on store

	uxtb r4, r2, ror #8
	uxtb r3, r2
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

	cmp r1, r14

	eor r2, r2, r3, ror #16
	eor r2, r2, r4, ror #8
	eor r2, r2, r5, ror #24
	str r2, [r1] // write back transformed key

	bne 1b

	pop {r4-r5, pc}

#endif
