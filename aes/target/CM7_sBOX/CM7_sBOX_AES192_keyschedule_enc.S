/*!
 * \file CM7_sBOX_AES192_keyshedule_enc.S
 * \brief cortex-m7 optimized aes192 key expansion
 *
 * utilizes basic sbox table
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only
#if __ARM_EABI__ && __thumb2__ && __ARM_FEATURE_DSP

// 8 rounds of rcon can be computed as left shift only

.syntax unified
.thumb
.text
//.section .itcm.text, "x"

.balign 8
// void CM7_sBOX_AES192_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM7_sBOX_AES192_keyschedule_enc
.type   CM7_sBOX_AES192_keyschedule_enc,%function
CM7_sBOX_AES192_keyschedule_enc:
	push {r4-r10, lr}

	movw r14, #:lower16:AES_sbox
	movt r14, #:upper16:AES_sbox

	//load key
	ldmia.w r1!, {r2-r7} // align loop entry

	mov.w r1, #0x01000000 // calculate rcon in highest byte to use a carry flag

	//just copy a key
	stmia.w r0!, {r2-r5} // align loop entry // r6, r7 stored at beggining of the loop

1:	and.w r12, r7, #0xff
	lsr.w r10, r7, #24

	strd r6,r7, [r0], #8

	uxtb r9, r7, ror #16
	ldrb r12, [r14, r12] // load sbox from Te2

	uxtb r8, r7, ror #8
	ldrb r10, [r14, r10] // load sbox from Te2

	eor r2, r2, r1, lsr #24 // rcon is in highest byte
	ldrb r9, [r14, r9] // load sbox from Te2

	eor r2, r2, r12, lsl #24
	ldrb r8, [r14, r8] // load sbox from Te2

	eor r2, r2, r10, lsl #16
	lsls.w r1, #1 // next rcon // cant .n even when epilogue aligned

	orr r8, r8, r9, lsl #8 // lower 16 bits
	eor.w r3, r2 // start now, there is bubble anyway

	eor.w r2, r8 // finish r2
	eor.w r3, r8

	eor.w r4, r3
	str.w r2, [r0], #4

	eor.w r5, r4
	str.w r3, [r0], #4

	strd r4,r5, [r0], #8

	bcs 2f
	eors r6, r5

	eors r7, r6
	b 1b // can bcc here at +1 cycles

2:
	pop {r4-r10, pc}

#endif
