/*!
 * \file CM0_FASTMULsBOX_OTFKS_AES128_encrypt.S
 * \brief cortex-m0 optimized AES encryption with on the fly key schedule
 *
 * optimized for code density, while maitaining decent performance
 * utilizes basic sbox table, requires single cycle multiplier
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
// void CM0_FASTMULsBOX_OTFKS_AES128_encrypt(const uint8_t* key, const uint8_t* in, uint8_t* out) {
.global CM0_FASTMULsBOX_OTFKS_AES128_encrypt
.type   CM0_FASTMULsBOX_OTFKS_AES128_encrypt,%function
CM0_FASTMULsBOX_OTFKS_AES128_encrypt:
	push {r4-r7, lr}
	mov r4, r8
	mov r5, r9
	mov r6, r10
	mov r7, r11
	push {r2, r4-r7} // stack out ptr

	ldmia r0!, {r4-r7} // load key
	ldm r1, {r0-r3} // load input

	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	push {r5-r7} // roundkey // rk[0] is kept in upper reg
	push {r0-r3} // state

	mov r11, r4 // rk[0]

	mov r4, sp // can't ldrb from sp
	movs r5, #0x1b
	ldr r6, =0x01010101
	ldr r7, =AES_sbox

	movs r0, #1 // rcon
	mov r12, r0

	// sp
	// +0  - state, 16 bytes
	// +16 - roundkey, 12 bytes (rk[0] is kept in r11)
	// +28 - out ptr
	// stacked registers
	// stacked registers

	// state elements will be represented with big endian order (transposed canonical state representation)
	// columns are loaded in little endian so right/left in shifts is in reverse wrt transposed canonical state representation

	// global allocation
	// r4 - pointer to sp, for byte extractions
	// r5 - 0x1b
	// r6 - 0x01010101
	// r7 - sbox
	// r8 - tmp c0
	// r9 - tmp c1
	// r10 - tmp c2
	// r11 - rk[0]
	// r12 - rcon
	// r14 - (need lr for inner calls)

	ldrb r0, [r4, #0] // skewed shiftrows
1:
	//state layout
	//  +0: s00,  +1: s10,  +2: s20,  +3: s30
	//  +4: s01,  +5: s11,  +6: s21,  +7: s31
	//  +8: s02,  +9: s12, +10: s22, +11: s32
	// +12: s03, +13: s13, +14: s23, +15: s33

	//final
	// c0 - s00`| s11`| s22`| s33`
	// c1 - s01`| s12`| s23`| s30`
	// c2 - s02`| s13`| s20`| s31`
	// c3 - s03`| s10`| s21`| s32`

	// col 0
	ldrb r1, [r4, #5]
	ldrb r2, [r4, #10]
	ldrb r3, [r4, #15]

	bl sbox_mix_inner

	mov r8, r0 // preserve before roundkey, can't do it now

	// col 1
	ldrb r0, [r4, #4]
	ldrb r1, [r4, #9]
	ldrb r2, [r4, #14]
	ldrb r3, [r4, #3]

	bl sbox_mix_inner

	mov r9, r0

	// col 2
	ldrb r0, [r4, #8]
	ldrb r1, [r4, #13]
	ldrb r2, [r4, #2]
	ldrb r3, [r4, #7]

	bl sbox_mix_inner

	mov r10, r0

	// col 3
	ldrb r0, [r4, #12]
	ldrb r1, [r4, #1]
	ldrb r2, [r4, #6]
	ldrb r3, [r4, #11]

	bl sbox_mix_inner

	// col 3 in r0

	// keyschedule and addroundkey
	mov r3, r12 // get rcon, stays in r3

	bl keyschedule_common

	mov r2, r8 // get col 0 back
	eors r2, r1

	mov r11, r1 // rk[0] done
	str r2, [sp, #0] // state[0] done

	// current allocation
	// r0 - col 3
	// r1 - rk[0]
	// r2 -
	// r3 - rcon

	ldr r2, [sp, #16+0] // load rk[1]
	eors r2, r1

	mov r1, r9 // get col 1 back
	eors r1, r2

	str r2, [sp, #16+0] // rk[1] done
	str r1, [sp, #4] // state[1] done

	// current allocation
	// r0 - col 3
	// r1 -
	// r2 - rk[1]
	// r3 - rcon

	ldr r1, [sp, #16+4] // load rk[2]
	eors r1, r2

	mov r2, r10 // get col 2 back
	eors r2, r1

	str r1, [sp, #16+4] // rk[2] done
	str r2, [sp, #8] // state[2] done

	// current allocation
	// r0 - col 3
	// r1 - rk[2]
	// r2 -
	// r3 - rcon

	ldr r2, [sp, #16+8] // load rk[3]
	eors r2, r1

	eors r0, r2

	str r2, [sp, #16+8] // rk[3] done
	str r0, [sp, #12] // state[3] done

	ldrb r0, [r4, #0] // skewed shiftrows

	lsls r3, #1 // next rcon
	cmp r3, #0x36 // final condition
	beq 2f

	mov r12, r3 // update rcon

	cmp r3, #0x80
	bls 1b // rcon is not secret
	mov r12, r5 // set rcon to 0x1b
	b 1b

2:	// final round

	// r0 extraction is skewed
	// rcon is in r3
	// r5, r6 are free

	ldr r5, [sp, #28] // out ptr

	// col 0
	bl keyschedule_common
	mov r6, r1

	ldrb r1, [r4, #5]
	ldrb r2, [r4, #10]
	ldrb r3, [r4, #15]

	bl sbox_addkey_final

	// col 1
	ldr r0, [sp, #16+0] // rk[1]
	eors r6, r0

	ldrb r0, [r4, #4]
	ldrb r1, [r4, #9]
	ldrb r2, [r4, #14]
	ldrb r3, [r4, #3]

	bl sbox_addkey_final

	// col 2
	ldr r0, [sp, #16+4] // rk[2]
	eors r6, r0

	ldrb r0, [r4, #8]
	ldrb r1, [r4, #13]
	ldrb r2, [r4, #2]
	ldrb r3, [r4, #7]

	bl sbox_addkey_final

	// col 3
	ldr r0, [sp, #16+8] // rk[3]
	eors r6, r0

	ldrb r0, [r4, #12]
	ldrb r1, [r4, #1]
	ldrb r2, [r4, #6]
	ldrb r3, [r4, #11]

	bl sbox_addkey_final

	//cleanup
	add sp, #16+12+4

	pop {r0-r3}
	mov r8, r0
	mov r9, r1
	mov r10, r2
	mov r11, r3

	pop {r4-r7, pc}

.balign 4
sbox_mix_inner:
	// expect extracted elements in r0-r3 (past the shiftrows)
	// return in r0

	ldrb r0, [r0, r7]
	ldrb r1, [r1, r7]
	ldrb r2, [r2, r7]
	ldrb r3, [r3, r7]

	// pack it
	lsls r1, #8
	orrs r0, r1

	lsls r2, #16
	orrs r0, r2

	lsls r3, #24
	orrs r0, r3

	// do mix columns as
	// tmp = s0 ^ s1 ^ s2 ^ s3
	// s0` ^= tmp ^ gmul2(s0^s1) // s1^s2^s3^gmul2(s0^s1)
	// s1` ^= tmp ^ gmul2(s1^s2) // s0^s2^s3^gmul2(s1^s2)
	// s2` ^= tmp ^ gmul2(s2^s3) // s0^s1^s3^gmul2(s2^s3)
	// s3` ^= tmp ^ gmul2(s3^s0) // s0^s1^s2^gmul2(s3^s0)

	// use approach with 1 more xor instead of rotation

	lsrs r1, r0, #8 // need to preserve input, so rors makes no diff
	lsls r2, r0, #24
	orrs r1, r2

	eors r1, r0 // s0^s1 | s1^s2 | s2^s3 | s3^s0

	rev16 r2, r1 // ror #16
	rev r2, r2 // ror #16

	eors r2, r1 // s0^s1^s2^s3 | s1^s2^s3^s0 | s2^s3^s0^s1 | s3^s0^s1^s2
	eors r0, r2 // s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	/*now mult r1 and eors it into r0

	do quad multiplication according to:
	// out = ((in & 0x7f7f7f7f) << 1) ^ (((in & 0x80808080) >> 7)) * 0x1b);

	modified to perform shifts first to avoid one extra mov
	// out = ((in << 1) & 0xfefefefe) ^ (((in >> 7) & 0x01010101) * 0x1b)
	*/

	lsrs r2, r1, #7
	ands r2, r6 // mask
	muls r2, r5 // get predicated reduction

	lsls r1, #1
	bics r1, r6 // & 0xfe // can also eors with r2

	eors r1, r2 // reduce
	eors r0, r1 // final

	bx lr

.balign 4
sbox_addkey_final:
	// expect extracted elements in r0-r3 (past the shiftrows)
	// roundkey in r6
	// out ptr in r5 (will be incremented)

	ldrb r0, [r0, r7]
	ldrb r1, [r1, r7]
	ldrb r2, [r2, r7]
	ldrb r3, [r3, r7]

	// pack it
	lsls r1, #8
	orrs r0, r1

	lsls r2, #16
	orrs r0, r2

	lsls r3, #24
	orrs r0, r3

	eors r0, r6 // apply rk

	stmia r5!, {r0}

	bx lr

.balign 4
keyschedule_common:
	// expects rcon in r3
	// outputs next rk[0] in r1
	// touches r2

	mov r1, r11 // load rk[0]

	ldrb r2, [r4, #16+8+1]
	ldrb r2, [r7, r2]
	eors r1, r2

	ldrb r2, [r4, #16+8+2]
	ldrb r2, [r7, r2]
	lsls r2, #8
	eors r1, r2

	ldrb r2, [r4, #16+8+3]
	ldrb r2, [r7, r2]
	lsls r2, #16
	eors r1, r2

	ldrb r2, [r4, #16+8+0]
	ldrb r2, [r7, r2]
	lsls r2, #24
	eors r1, r2

	eors r1, r3 // apply rcon

	bx lr

#endif
