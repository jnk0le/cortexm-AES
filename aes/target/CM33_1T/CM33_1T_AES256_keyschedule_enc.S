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

	ldmia r1!, {r3-r10} // load key

	str r3, [r0], #4 // need to split stmia due to rcon

	mov.w r1, #0x01000000 // calculate rcon in highest byte to use a carry flag
	eor r3, r3, r1, lsr #24 // rcon application is skewed into g transform part

	stmia r0!, {r4-r6} // copy first half of the key
	b 2f // nothing to dual issue (could do stmia without that rcon)

	// allocation
	// r0 - rk ptr
	// r1 - rcon
	// r2 - tmp
	// r3 - rk0
	// r4 - rk1
	// r5 - rk2
	// r6 - rk3
	// r7 - rk4
	// r8 - rk5
	// r9 - rk6
	// r10 - rk7
	// r11 - tmp
	// r12 - Te2 ptr

.balign 4
1:	// g transform // just sbox, no shufflng
	uxtb r11, r6, ror #8
	ldrb r11, [r12, r11, lsl #2] // load sbox from Te2

	uxtb r2, r6, ror #16
	eor r7, r7, r11, lsl #8
	ldrb r2, [r12, r2, lsl #2] // load sbox from Te2

	uxtb r11, r6, ror #24
	eor r7, r7, r2, lsl #16
	ldrb r11, [r12, r11, lsl #2] // load sbox from Te2

	uxtb r2, r6
	eor r7, r7, r11, lsl #24
	ldrb r2, [r12, r2, lsl #2] // load sbox from Te2

	eor r3, r3, r1, lsr #24 // apply rcon here as we have a scheduling gap
	eors r7, r2

	eor.w r8, r7
	eor.w r9, r8
	eor.w r10, r9

2:	stmia r0!, {r7-r10}

	uxtb r11, r10 // then lsl #24
	ldrb r11, [r12, r11, lsl #2] // load sbox from Te2

	uxtb r2, r10, ror #16 // then lsl #8
	eor r3, r3, r11, lsl #24
	ldrb r2, [r12, r2, lsl #2] // load sbox from Te2

	uxtb r11, r10, ror #24 // then lsl #16
	eor r3, r3, r2, lsl #8
	ldrb r11, [r12, r11, lsl #2] // load sbox from Te2

	uxtb r2, r10, ror #8 // then lsl #0
	eor r3, r3, r11, lsl #16
	ldrb r2, [r12, r2, lsl #2] // load sbox from Te2

	lsls r1, #1 // next rcon
	itttt ne // rcon is never zero, also avoids dirty workaround required by `it al`
	eorne r3, r2

	eorne r4, r3
	eorne r5, r4
	eorne r6, r5

	stmia r0!, {r3-r6}
	bpl 1b // break at 0x80000000

	pop {r4-r11}
	bx lr // could split and skew stmia, for dual issue, but not worth in key expansion

#endif
