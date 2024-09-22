/*!
 * \file CM85_1T_AES128_keyschedule_enc.S
 * \brief
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only (__ARM_ARCH_8_1M_MAIN__ doesn't work)
#if __ARM_EABI__ && __thumb2__ && (__ARM_FEATURE_MVE & 0b01)

// 10 rounds of rcon can be computed as left shift + conditional reload of rcon to 0x1b after 0x80
// it can also serve as loop counter to reduce register pressure

.syntax unified
.thumb
.text

.balign 8
// void CM85_1T_AES128_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM85_1T_AES128_keyschedule_enc
.type   CM85_1T_AES128_keyschedule_enc,%function
CM85_1T_AES128_keyschedule_enc:
	strd r4,r5, [sp, #-24]!
	movw r12, #:lower16:AES_Te2

	strd r6,r7, [sp, #8]
	movt r12, #:upper16:AES_Te2

	// load key, store rk
	ldrd r2,r3, [r1], #8
	strd r2,r3, [r0], #8

	ldrd r4,r5, [r1], #8
	strd r4,r5, [r0], #8

	mov.w r7, 0x01000000 // rcon
	strd r8,lr, [sp, #16]

	//global allocation
	// r0 - rk_p
	// r1 -
	// r2 - rk[0]
	// r3 - rk[1]
	// r4 - rk[2]
	// r5 - rk[3]
	// r6 -
	// r7 - rcon
	// r8 -
	// r12 - Te2
	// r14 -

1:
	lsrs r1, r5, #24 // lsl 16
	ubfx r14, r5, #0, #8 // lsl 24

	eor.w r2, r2, r7, lsr #24 // rcon is in highest byte
	ldrb.w r1, [r12, r1, lsl #2]

	ubfx r8, r5, #16, #8 // lsl 8
	ldrb.w r14, [r12, r14, lsl #2]

	ubfx r6, r5, #8, #8 // lsl 0
	ldrb.w r8, [r12, r8, lsl #2]

	eor.w r2, r2, r1, lsl #16
	ldrb.w r6, [r12, r6, lsl #2]

	eor.w r2, r2, r14, lsl #24
	orr.w r6, r6, r8, lsl #8 // xor both later

	lsls r7, #1 // next rcon
	it cs // 0x1b reduction when carry set
	movcs r7, #0x1b000000

	eors r3, r2 // r6 will be applied later, cannot use it now
	eors r3, r6

	eors r4, r3
	eors r5, r4

	cmp r7, #0x6c000000
	eor.w r2, r2, r6 // apply skipped r6, due to latency pressure

	strd r2,r3, [r0], #8
	strd r4,r5, [r0], #8 // runs on slippery condition anyway
	bne 1b

	pop {r4-r8, pc}

#endif
