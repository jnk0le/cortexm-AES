/*!
 * \file CM0_sBOX_AES192_keyschedule_enc.S
 * \brief
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only
#if __ARM_EABI__

 // 8 rounds of rcon can be computed as left shift only

.syntax unified
.thumb
.text

.balign 4
// void CM0_sBOX_AES192_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM0_sBOX_AES192_keyschedule_enc
.type   CM0_sBOX_AES192_keyschedule_enc,%function
CM0_sBOX_AES192_keyschedule_enc:
	push {r4-r7, lr}

	ldmia r1!, {r2-r7} // load key
	stmia r0!, {r2-r7} // just copy a key

	movs r1, #1
	mov r12, r1 // save rcon

	mov r14, r0 // save rk

	ldr r0, =AES_sbox

	lsrs r1, r7, #8 // skewed loop
1:
	uxtb r1, r1
	ldrb r1, [r0, r1]
	eors r2, r1

	lsrs r1, r7, #16
	uxtb r1, r1
	ldrb r1, [r0, r1]
	lsls r1, #8
	eors r2, r1

	lsrs r1, r7, #24
	ldrb r1, [r0, r1]
	lsls r1, #16
	eors r2, r1

	uxtb r1, r7
	ldrb r1, [r0, r1]
	lsls r1, #24
	eors r2, r1

	mov r1, r12 // get rcon
	eors r2, r1 // apply rcon

	eors r3, r2
	eors r4, r3
	eors r5, r4

	cmp r1, #0x40
	mov r1, r14 // get rk
	bhi 2f // we need one round with 0x80 rcon applied

	add r12, r12 // left shift rcon

	eors r6, r5
	eors r7, r6

	stmia r1!, {r2-r7} // write full roundkey
	mov r14, r1 // put rk back

	lsrs r1, r7, #8 // skewed loop
	b 1b

2:	stmia r1!, {r2-r5} // only 4 entries have to be written

	pop {r4-r7, pc}

#endif
