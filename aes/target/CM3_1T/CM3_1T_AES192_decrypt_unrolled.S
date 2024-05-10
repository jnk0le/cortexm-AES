/*!
 * \file CM3_1T_AES_192_decrypt_unrolled.S
 * \brief
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * Peter Schwabe & Ko Stoffelen @2016
 * \license SPDX-License-Identifier: MIT
 * \date 18 jul 2018
 */

// compile for compatible targets only
#if __ARM_EABI__ && __thumb2__

.include "aes/target/CM3_1T/CM3_1T_AES_common.inc"

.syntax unified
.thumb
.text

.align 3
// void CM3_1T_AES192_decrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out) {
.global CM3_1T_AES192_decrypt_unrolled
.type   CM3_1T_AES192_decrypt_unrolled,%function
CM3_1T_AES192_decrypt_unrolled:
	push {r2, r4-r11, lr} //stack output pointer

	add r12, r0, #192 // 12 rounds * 16

	movw r14, #:lower16:AES_Td2
	movt r14, #:upper16:AES_Td2

	//load input
	//ldm r1, {r4-r7}
	ldr r4, [r1, #0]
	ldr r5, [r1, #4]
	ldr r6, [r1, #8]
	ldr r7, [r1, #12]

	//load initial round key
	//ldm r12, {r0-r3}
	ldr r0, [r12, #0]
	ldr r1, [r12, #4]
	ldr r2, [r12, #8]
	ldr r3, [r12, #12]

	//initial addroundkey
	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	CM3_1T_unrolled_dec_round // 1
	CM3_1T_unrolled_dec_round // 2
	CM3_1T_unrolled_dec_round // 3
	CM3_1T_unrolled_dec_round // 4
	CM3_1T_unrolled_dec_round // 5
	CM3_1T_unrolled_dec_round // 6
	CM3_1T_unrolled_dec_round // 7
	CM3_1T_unrolled_dec_round // 8
	CM3_1T_unrolled_dec_round // 9
	CM3_1T_unrolled_dec_round // 10
	CM3_1T_unrolled_dec_round // 11

	// final round
	movw r14, #:lower16:AES_inv_sbox
	movt r14, #:upper16:AES_inv_sbox

	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r8, [r12, #-16]
	ldr r9, [r12, #-12]
	ldr r10, [r12, #-8]
	ldr r11, [r12, #-4]
	ldrb r0, [r14, r0]
	ldrb r1, [r14, r1]
	ldrb r2, [r14, r2]
	ldrb r3, [r14, r3]
	eor r8, r0
	eor r9, r1
	eor r10, r2
	eor r11, r3

	uxtb r0, r7, ror #8
	uxtb r1, r4, ror #8
	uxtb r2, r5, ror #8
	uxtb r3, r6, ror #8
	ldrb r0, [r14, r0]
	ldrb r1, [r14, r1]
	ldrb r2, [r14, r2]
	ldrb r3, [r14, r3]
	eor r8, r8, r0, lsl #8
	eor r9, r9, r1, lsl #8
	eor r10, r10, r2, lsl #8
	eor r11, r11, r3, lsl #8

	uxtb r0, r6, ror #16
	uxtb r1, r7, ror #16
	uxtb r2, r4, ror #16
	uxtb r3, r5, ror #16

	lsrs r5, #24
	lsrs r6, #24

	uxtb r7, r7, ror #24 // align loads to 4 bytes
	uxtb r12, r4, ror #24

	ldr r4, [sp], #4 // load output pointer and clear stack

	ldrb r0, [r14, r0]
	ldrb r1, [r14, r1]
	ldrb r2, [r14, r2]
	ldrb r3, [r14, r3]

	ldrb r5, [r14, r5]
	ldrb r6, [r14, r6]
	ldrb r7, [r14, r7]
	ldrb r12, [r14, r12]

	eor r8, r8, r0, lsl #16
	eor r9, r9, r1, lsl #16
	eor r10, r10, r2, lsl #16
	eor r11, r11, r3, lsl #16

	eor r0, r8, r5, lsl #24
	eor r1, r9, r6, lsl #24
	eor r2, r10, r7, lsl #24
	eor r3, r11, r12, lsl #24

	str r0, [r4, #0]
	str r1, [r4, #4]
	str r2, [r4, #8]
	str r3, [r4, #12]

	pop {r4-r11, pc}

#endif
