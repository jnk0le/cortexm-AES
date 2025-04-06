/*!
 * \file CM0_d4T_AES_keyschedule_dec.S
 * \brief cortex-m0 optimized aes decryption keyschedule
 *
 * performs equivalent inverse cipher transformation on expanded encryption key
 * order of round keys is not inverted - decryption will read it in reverse
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only
#if __ARM_EABI__

.syntax unified
.thumb
.text

.balign 4
// void CM0_d4T_AES_keyschedule_dec(uint8_t* rk, size_t rounds) {
.global CM0_d4T_AES_keyschedule_dec
.type   CM0_d4T_AES_keyschedule_dec,%function
CM0_d4T_AES_keyschedule_dec:
	push {r4-r6, lr}

	//first and last block is ommited
	//rk_end-16 = rk + rounds * 16
	lsls r1, #4
	add r1, r0
	adds r0, #16

	// sbox is at
	// bank1 - +1 +2
	// bank2 - +6 +7
	// bank3 - +8 +11
	// bank4 - +12 +13

	ldr r5, =(AES_d4Te + 1)
	ldr r6, =AES_d4Td

	// 31 insn nomul inv ???
	// 26 insn fastmul inv ????
1:
	ldr r2, [r0]

	uxtb r3, r2
	lsls r3, #4
	ldrb r3, [r5, r3] // load sbox from Te2
	lsls r3, #4
	ldr r3, [r6, r3]

	lsrs r4, r2, #24
	lsls r4, #4
	ldrb r4, [r5, r4] // load sbox from Te2
	lsls r4, #4
	adds r4, #12 // Td3 offset
	ldr r4, [r6, r4]

	eors r3, r4

	rev16 r2, r2

	uxtb r4, r2
	lsls r4, #4
	ldrb r4, [r5, r4] // load sbox from Te2
	lsls r4, #4
	adds r4, #4 // Td1 offset
	ldr r4, [r6, r4]

	eors r3, r4

	lsrs r4, r2, #24
	lsls r4, #4
	ldrb r4, [r5, r4] // load sbox from Te2
	lsls r4, #4
	adds r4, #8 // Td2 offset
	ldr r4, [r6, r4]

	eors r3, r4

	str r3, [r0]
	adds r0, #4

	cmp r1, r0
	bne 1b

	pop {r4-r6, pc}

#endif
