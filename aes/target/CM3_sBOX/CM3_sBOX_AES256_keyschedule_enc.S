/*!
 * \file CM3_sBOX_AES256_keyshedule_enc.S
 * \brief
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only
#if __ARM_EABI__ && __thumb2__

// 7 rounds of rcon can be computed as left shift only

.syntax unified
.thumb
.text

.balign 4
// void CM3_sBOX_AES256_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM3_sBOX_AES256_keyschedule_enc
.type   CM3_sBOX_AES256_keyschedule_enc,%function
CM3_sBOX_AES256_keyschedule_enc:
	push {r4-r11, lr}

	ldmia r1!, {r2-r9} //load key

	movw r1, #:lower16:AES_sbox
	movt r1, #:upper16:AES_sbox
	str r1, [sp, #-8]! // put and reserve Te2 on stack before looping

	mov.w r1, #0x01000000 // calculate rcon in highest byte to use a carry flag

	//sp+0 - sbox
	//sp+4 - rcon

1:	stmia r0!, {r2-r9} // store initial or previous round

	eor r2, r2, r1, lsr #24 // rcon is in highest byte
	lsls r1, #1 // next rcon
	str r1, [sp, #4] // spill rcon

	uxtb r10, r9, ror #8
	uxtb r11, r9, ror #16
	uxtb r12, r9, ror #24
	uxtb r14, r9

	ldr.w r1, [sp, #0] // get Te2 // cannot be pipelined anyway // align loads to 4 bytes

	ldrb r10, [r1, r10]
	ldrb r11, [r1, r11]
	ldrb r12, [r1, r12]
	ldrb r14, [r1, r14]

	eor r2, r2, r10
	eor r2, r2, r11, lsl #8
	eor r2, r2, r12, lsl #16
	eor r2, r2, r14, lsl #24

	// instead of 3x eor.w + bmi.w, put eors after branch and in epilogue // somehow saves 6 cycles at 0ws
	bmi 2f

	eors r3, r2
	eors r4, r3
	eors r5, r4

	uxtb r10, r5, ror #16
	uxtb r11, r5, ror #8
	uxtb r12, r5
	uxtb r14, r5, ror #24

	ldrb r10, [r1, r10]
	ldrb r11, [r1, r11]
	ldrb r12, [r1, r12]
	ldrb r14, [r1, r14]
	ldr.w r1, [sp, #4] // get rcon // will lose cycles if not .w

	eor r6, r6, r10, lsl #16
	eor r6, r6, r11, lsl #8
	eor r6, r12
	eor r6, r6, r14, lsl #24
	eors r7, r6
	eor r8, r7
	eor r9, r8

	b 1b

2:	eors r3, r2
	eors r4, r3
	eors r5, r4

	stmia r0!, {r2-r5} // write only 4 words at the last round

	add sp, #8 // faster than dummy pops
	pop {r4-r11, pc}

#endif
