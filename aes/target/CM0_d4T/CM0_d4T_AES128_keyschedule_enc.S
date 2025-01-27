/*!
 * \file CM0_d4T_AES128_keyschedule_enc.S
 * \brief
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only
#if __ARM_EABI__

// 10 rounds of rcon can be computed as left shift + conditional reload of rcon to 0x1b after 0x80
// it can also serve as loop counter to reduce register pressure

.syntax unified
.thumb
.text

.balign 4
// void CM0_d4T_AES128_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM0_d4T_AES128_keyschedule_enc
.type   CM0_d4T_AES128_keyschedule_enc,%function
CM0_d4T_AES128_keyschedule_enc:
	push {r4-r7}

	ldmia r1!, {r4-r7} // load key

	movs r1, #1 // rcon

	// sbox is at
	// bank1 - +1 +2
	// bank2 - +6 +7
	// bank3 - +8 +11
	// bank4 - +12 +13

	ldr r2, =(AES_d4Te + 6)

	stmia r0!, {r4-r7} //just copy a key

	lsrs r3, r7, #8 // skewed loop
1:
	uxtb r3, r3
	lsls r3, #4
	ldrb r3, [r2, r3]
	eors r4, r3

	lsrs r3, r7, #16
	uxtb r3, r3
	lsls r3, #4
	ldrb r3, [r2, r3]
	lsls r3, #8
	eors r4, r3

	lsrs r3, r7, #24
	lsls r3, #4
	ldrb r3, [r2, r3]
	lsls r3, #16
	eors r4, r3

	uxtb r3, r7
	lsls r3, #4
	ldrb r3, [r2, r3]
	lsls r3, #24
	eors r4, r3

	eors r4, r1 // apply rcon
	eors r5, r4
	eors r6, r5
	eors r7, r6

	stmia r0!, {r4-r7} // write roundkey

	cmp r1, #0x36 // final condition
	beq 2f

	lsrs r3, r7, #8 // skewed loop

	lsls r1, #1 // next rcon
	cmp r1, #0x80
	bls 1b // rcon is not secret
	movs r1, #0x1b
	b 1b

2:	pop {r4-r7}
	bx lr

#endif
