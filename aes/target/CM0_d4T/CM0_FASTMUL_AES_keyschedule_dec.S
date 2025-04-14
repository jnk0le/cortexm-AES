/*!
 * \file CM0_d4T_AES_keyschedule_dec.S
 * \brief cortex-m0 optimized aes decryption keyschedule
 *
 * performs equivalent inverse cipher transformation on expanded encryption key
 * order of round keys is not inverted - decryption will read it in reverse
 *
 * requires single cycle multiplier
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
// void CM0_FASTMUL_AES_keyschedule_dec(uint8_t* rk, size_t rounds) {
.global CM0_FASTMUL_AES_keyschedule_dec
.type   CM0_FASTMUL_AES_keyschedule_dec,%function
CM0_FASTMUL_AES_keyschedule_dec:
	push {r4-r7, lr}

	//first and last block is ommited
	//rk_end-16 = rk + rounds * 16
	lsls r1, #4
	add r1, r0
	adds r0, #16

	mov r14, r1 // final condition

	ldr r6, =0x01010101
	movs r7, 0x1b

	// cycles per inv mix columns
	// 40 insn nomul
	// 32 insn fastmul
	// 35 insn Td[sbox[x]]

1:
	ldr r2, [r0]

	//expand S{1} to S{2}, S{4}, S{8}
	//all of them have to be preserved

	/* do quad multiplication according to:
	// out = ((in & 0x7f7f7f7f) << 1) ^ (((in & 0x80808080) >> 7)) * 0x1b);

	some calculations are modified to perform shifts first to avoid extra moves
	// out = ((in << 1) & 0xfefefefe) ^ (((in >> 7) & 0x01010101) * 0x1b)
	*/

	lsrs r3, r2, #7
	ands r3, r6 // mask
	muls r3, r7 // get predicated reduction

	lsls r4, r2, #1
	bics r4, r6 // & 0xfe

	eors r3, r4 // S{2}

	lsrs r4, r3, #7
	ands r4, r6 // mask
	muls r4, r7 // get predicated reduction

	lsls r5, r3, #1
	bics r5, r6 // & 0xfe

	eors r4, r5 // S{4}

	lsrs r5, r4, #7
	ands r5, r6 // mask
	muls r5, r7 // get predicated reduction

	lsls r1, r4, #1
	bics r1, r6 // & 0xfe

	eors r5, r1 // S{8}

	// r1 -
	// r2 - S{1}
	// r3 - S{2}
	// r4 - S{4}
	// r5 -	S{8}

	eors r2, r5 // S{9}
	eors r5, r3
	eors r5, r4 // S{e}
	eors r3, r2 // S{b}
	eors r4, r2 // S{d}

	// S{9} - ror #24
	// S{b} - ror #8
	// S{d} - ror #16
	// S{e} - ror #0

	movs r1, #24
	rors r2, r1

	eors r2, r5 // s0{e}^s3{9} | s1{e}^s0{9} | s2{e}^s1{9} | s3{e}^s2{9}

	movs r1, #8
	rors r3, r1

	eors r2, r3 // s0{e}^s1{b}^s3{9} | s1{e}^s2{b}^s0{9} | s2{e}^s3{b}^s1{9} | s3{e}^s0{b}^s2{9}

	rev16 r4, r4
	rev r4, r4

	eors r2, r4 // s0{e}^s1{b}^s2{d}^s3{9} | s1{e}^s2{b}^s3{d}^s0{9} | s2{e}^s3{b}^s0{d}^s1{9} | s3{e}^s0{b}^s1{d}^s2{9}

	str r2, [r0]
	adds r0, #4

	cmp r14, r0
	bne 1b

	pop {r4-r7, pc}

#endif
