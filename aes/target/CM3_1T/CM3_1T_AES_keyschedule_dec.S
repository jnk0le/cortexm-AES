/*!
 * \file CM3_1T_AES_keyschedule_dec.S
 * \brief cortex-m3/4 optimized aes decryption keyschedule
 *
 * performs equivalent inverse cipher transformation on expanded encryption key
 * order of round keys is not inverted - decryption will read it in reverse
 *
 * utilizes Te2 and Td2 tables
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
// void CM3_1T_AES_keyschedule_dec(uint8_t* rk, size_t rounds) {
.global CM3_1T_AES_keyschedule_dec
.type   CM3_1T_AES_keyschedule_dec,%function
CM3_1T_AES_keyschedule_dec:
	push {r4-r5, lr}

	//first and last block is ommited
	//rk_end-16 = rk + rounds * 16
	add r1, r0, r1, lsl #4
	adds r0, #16

	movw r14, #:lower16:AES_Te2
	movt r14, #:upper16:AES_Te2
	movw r12, #:lower16:AES_Td2
	movt r12, #:upper16:AES_Td2

1:	ldr r2, [r1, #-4]! // can also go forward on r0 but requires negative offset on store

	uxtb r4, r2, ror #8
	uxtb r3, r2
	lsrs r5, r2, #24
	uxtb r2, r2, ror #16

	ldrb r3, [r14, r3, lsl #2] // load sbox from Te2
	ldrb r4, [r14, r4, lsl #2] // load sbox from Te2
	ldrb r2, [r14, r2, lsl #2] // load sbox from Te2
	ldrb r5, [r14, r5, lsl #2] // load sbox from Te2
	ldr r3, [r12, r3, lsl #2]
	ldr r4, [r12, r4, lsl #2]
	ldr r2, [r12, r2, lsl #2]
	ldr r5, [r12, r5, lsl #2]

	cmp r1, r0

	eor r2, r2, r3, ror #16
	eor r2, r2, r4, ror #8
	eor r2, r2, r5, ror #24

	str r2, [r1] // write back transformed key

	bne 1b

	pop {r4-r5, pc}

#endif
