/*!
 * \file CM33_1T_AES128_keyschedule_enc.S
 * \brief cortex-m33 optimized aes128 key expansion
 *
 * utilizes Te2 table
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only
#if __ARM_EABI__ && __thumb2__

// 10 rounds of rcon can be computed as left shift + conditional reload of rcon to 0x1b after 0x80
// it can also serve as loop counter to reduce register pressure

.syntax unified
.thumb
.text

.balign 4
// void CM33_1T_AES128_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM33_1T_AES128_keyschedule_enc
.type   CM33_1T_AES128_keyschedule_enc,%function
CM33_1T_AES128_keyschedule_enc:
	push {r4-r7}

	movw r12, #:lower16:AES_Te2
	movt r12, #:upper16:AES_Te2

	ldmia.w r1, {r4-r7} // load key once // align loop entry to 8 bytes
	mov.w r1, #0x01000000 // calculate rcon in highest byte to use a carry flag

	//just copy a key
	stmia r0!, {r4-r7}

1:	uxtb r2, r7 // then lsl #24
	eor r4, r4, r1, lsr #24 // rcon is in highest byte
	ldrb r2, [r12, r2, lsl #2] // load sbox from Te2

	uxtb r3, r7, ror #16 // then lsl #8
	eor r4, r4, r2, lsl #24
	ldrb r3, [r12, r3, lsl #2] // load sbox from Te2

	uxtb r2, r7, ror #24 // then lsl #16
	eor r4, r4, r3, lsl #8
	ldrb r2, [r12, r2, lsl #2] // load sbox from Te2

	uxtb r3, r7, ror #8 // then lsl #0
	eor r4, r4, r2, lsl #16
	ldrb r3, [r12, r3, lsl #2] // load sbox from Te2

	lsls r1, #1 // next rcon
	eors r4, r4, r3

	it cs // 0x1b reduction when carry set
	movcs r1, #0x1b000000

	eors r5, r4
	eors r6, r5
	eors r7, r6

	cmp r1, #0x6c000000

	stmia r0!, {r4-r7} // write roundkey
	bne 1b

	pop {r4-r7}
	bx lr

#endif
