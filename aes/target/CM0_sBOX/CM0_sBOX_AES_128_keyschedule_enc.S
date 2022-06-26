/*!
 * \file CM0_sBOX_AES_128_keyschedule_enc.S
 * \brief
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 * \date 17 oct 2021
 */

// 10 rounds of rcon can be computed as left shift + conditional reload of rcon to 0x1b after 0x80
// it can also serve as loop counter to reduce register pressure

.syntax unified
.thumb
.text

.align 2
// void CM0_sBOX_AES_128_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM0_sBOX_AES_128_keyschedule_enc
.type   CM0_sBOX_AES_128_keyschedule_enc,%function
	nop // align loop entry
CM0_sBOX_AES_128_keyschedule_enc:
	push {r4-r7}

	ldmia r1!, {r4-r7} // load key

	movs r1, #1 // rcon
	ldr r2, =AES_sbox

	stmia r0!, {r4-r7} //just copy a key

1:	lsrs r3, r7, #8
	uxtb r3, r3
	ldrb r3, [r2, r3]
	eors r4, r3

	lsrs r3, r7, #16
	uxtb r3, r3
	ldrb r3, [r2, r3]
	lsls r3, #8
	eors r4, r3

	lsrs r3, r7, #24
	ldrb r3, [r2, r3]
	lsls r3, #16
	eors r4, r3

	uxtb r3, r7
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

	lsls r1, #1 // next rcon
	cmp r1, #0x80
	bls 1b // rcon is not secret
	movs r1, #0x1b
	b 1b

2:	pop {r4-r7}
	bx lr
