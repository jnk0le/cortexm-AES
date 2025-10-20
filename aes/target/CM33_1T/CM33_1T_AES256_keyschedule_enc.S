/*!
 * \file CM33_1T_AES256_keyschedule_enc.S
 * \brief cortex-m33 optimized aes256 key expansion
 *
 * utilizes Te2 table
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
// void CM33_1T_AES256_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM33_1T_AES256_keyschedule_enc
.type   CM33_1T_AES256_keyschedule_enc,%function
CM33_1T_AES256_keyschedule_enc:
	push {r4-r11}

	movw r12, #:lower16:AES_Te2
	movt r12, #:upper16:AES_Te2

	ldmia r1!, {r4-r11} // load key

	stmia r0!, {r4-r11} // just copy key

	mov.w r1, #0x01000000 // calculate rcon in highest byte to use a carry flag
	eor r4, r4, r1, lsr #24 // rcon application is skewed into g transform part

	b 2f // nothing to dual issue (could do some skewing of stmia's without that rcon)

	// allocation
	// r0 - rk ptr
	// r1 - rcon
	// r2 - tmp
	// r3 - tmp
	// r4 - rk0
	// r5 - rk1
	// r6 - rk2
	// r7 - rk3
	// r8 - rk4
	// r9 - rk5
	// r10 - rk6
	// r11 - rk7
	// r12 - Te2 ptr

.balign 4
1:	//g transform // just sbox, no shufflng
	uxtb r2, r7, ror #8
	ldrb r2, [r12, r2, lsl #2] // load sbox from Te2

	uxtb r3, r7, ror #16
	eor r8, r8, r2, lsl #8
	ldrb r3, [r12, r3, lsl #2] // load sbox from Te2

	uxtb r2, r7, ror #24
	eor r8, r8, r3, lsl #16
	ldrb r2, [r12, r2, lsl #2] // load sbox from Te2

	uxtb.w r3, r7 // can't .n without a pair
	eor r8, r8, r2, lsl #24
	ldrb r3, [r12, r3, lsl #2] // load sbox from Te2

	eor r4, r4, r1, lsr #24 // apply rcon here as we have a scheduling gap
	eor.w r8, r3

	eor.w r9, r8
	eor.w r10, r9
	eor.w r11, r10

	stmia r0!, {r8-r11} // store after start so prologue dual issue??????

2:
	uxtb r2, r11 // then lsl #24
	ldrb r2, [r12, r2, lsl #2] // load sbox from Te2

	uxtb r3, r11, ror #16 // then lsl #8
	eor r4, r4, r2, lsl #24
	ldrb r3, [r12, r3, lsl #2] // load sbox from Te2

	uxtb r2, r11, ror #24 // then lsl #16
	eor r4, r4, r3, lsl #8
	ldrb r2, [r12, r2, lsl #2] // load sbox from Te2

	uxtb r3, r11, ror #8 // then lsl #0
	eor r4, r4, r2, lsl #16
	ldrb r3, [r12, r3, lsl #2] // load sbox from Te2

	lsls r1, #1 // next rcon
	eor.w r4, r3

	eor.w r5, r4
	eor.w r6, r5
	eor.w r7, r6

	stmia r0!, {r4-r7}
	bpl 1b // break at 0x80000000

	pop {r4-r11}
	bx lr // nothing to dual issue

#endif
