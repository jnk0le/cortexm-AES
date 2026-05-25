/*!
 * \file CM0_FASTMULsBOX_OTFKS_AES128_decrypt.S
 * \brief cortex-m0 optimized AES decryption with on the fly key schedule
 *
 * optimized for code density, while maitaining decent performance
 * utilizes basic sbox and inv_sbox tables, requires single cycle multiplier
 *
 * key must be expanded to the last roundkey
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
	nop // align loop entry
// void CM0_FASTMULsBOX_OTFKS_AES128_decrypt(const uint8_t* last_rk, const uint8_t* in, uint8_t* out) {
.global CM0_FASTMULsBOX_OTFKS_AES128_decrypt
.type   CM0_FASTMULsBOX_OTFKS_AES128_decrypt,%function
CM0_FASTMULsBOX_OTFKS_AES128_decrypt:
	push {r4-r7, lr}
	mov r4, r8
	mov r5, r9
	mov r6, r10
	mov r7, r11
	push {r2, r4-r7} // stack out ptr

	ldmia r0!, {r4-r7} // load key
	ldm r1, {r0-r3} // load input

	// initial addroundkey
	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	push {r4-r7} // roundkey
	push {r0-r3} // state

	add r4, sp, #16 // keyschedule restores it to sp

	ldr r6, =0x01010101
	movs r5, #0x36 // initial rcon

	ldr r7, =AES_inv_sbox
	mov r12, r5 // store rcon

	ldr r5, =AES_sbox
	mov r11, r5

	bl inv_keyschedule // leaves rcon in r5

	// sp
	// +0  - state, 16 bytes
	// +16 - roundkey, 16bytes
	// +32 - out ptr
	// stacked registers
	// stacked registers

	// state elements will be represented with big endian order (transposed canonical state representation)
	// columns are loaded in little endian so right/left in shifts is in reverse wrt transposed canonical state representation

	// global allocation
	// r4 - pointer to sp, for byte extractions (sp+16 for keyschedules)
	// r5 - tmp (0x1b)
	// r6 - 0x01010101
	// r7 - inv_sbox
	// r8 - tmp c1
	// r9 - tmp c2
	// r10 - tmp c3
	// r11 - sbox (for keyschedule)
	// r12 - rcon
	// r14 - (need lr for inner calls)

1:
	mov r12, r5 // restore rcon

	//state layout
	//  +0: s00,  +1: s10,  +2: s20,  +3: s30
	//  +4: s01,  +5: s11,  +6: s21,  +7: s31
	//  +8: s02,  +9: s12, +10: s22, +11: s32
	// +12: s03, +13: s13, +14: s23, +15: s33

	//final
	// c0 - s00`| s13`| s22`| s31`
	// c1 - s01`| s10`| s23`| s32`
	// c2 - s02`| s11`| s20`| s33`
	// c3 - s03`| s12`| s21`| s30`

	// col 1
	mov r5, r1 // roundkey is still in registers after keyschedule

	ldrb r0, [r4, #4]
	ldrb r1, [r4, #1]
	ldrb r2, [r4, #14]
	ldrb r3, [r4, #11]

	bl inv_sbox_addkey_mix_inner

	mov r8, r0

	// col 2
	ldrb r0, [r4, #8]
	ldrb r1, [r4, #5]
	ldrb r2, [r4, #2]
	ldrb r3, [r4, #15]

	ldr r5, [sp, #16+8] // roundkey

	bl inv_sbox_addkey_mix_inner

	mov r9, r0

	// col 3
	ldrb r0, [r4, #12]
	ldrb r1, [r4, #9]
	ldrb r2, [r4, #6]
	ldrb r3, [r4, #3]

	ldr r5, [sp, #16+12] // roundkey

	bl inv_sbox_addkey_mix_inner

	mov r10, r0

	// col 0
	ldrb r0, [r4, #0]
	ldrb r1, [r4, #13]
	ldrb r2, [r4, #10]
	ldrb r3, [r4, #7]

	ldr r5, [sp, #16+0] // roundkey

	bl inv_sbox_addkey_mix_inner

	mov r1, r8
	mov r2, r9
	mov r3, r10

	stmia r4!, {r0-r3} // store state
	// r4 now points to roundkey, will be restored in keyschedule

	//keyschedule for next round
	bl inv_keyschedule
	// rcon is in r5, already shifted

	// condition flags come from shift inside keyschedule, reduce when carried with 0x0d left
	// branch away as this is done only once
	// `hi` condition checks for carry set and zero cleared (have to finish loop when reached zero)
	bhi rcon_reduce // rcon is not secret

	// rcon is restored at beginning of the loop
	bne 1b

	// final round
	// r6 is free

	ldr r6, [sp, #16+16+0] // out ptr

	// col 0
	mov r5, r0 // roundkey is still in registers after keyschedule

	ldrb r0, [r4, #0]
	ldrb r1, [r4, #13]
	ldrb r2, [r4, #10]
	ldrb r3, [r4, #7]

	bl inv_sbox_addkey_inner_final

	// col 1
	ldrb r0, [r4, #4]
	ldrb r1, [r4, #1]
	ldrb r2, [r4, #14]
	ldrb r3, [r4, #11]

	ldr r5, [sp, #16+4] // roundkey

	bl inv_sbox_addkey_inner_final

	// col 2
	ldrb r0, [r4, #8]
	ldrb r1, [r4, #5]
	ldrb r2, [r4, #2]
	ldrb r3, [r4, #15]

	ldr r5, [sp, #16+8] // roundkey

	bl inv_sbox_addkey_inner_final

	// col 3
	ldrb r0, [r4, #12]
	ldrb r1, [r4, #9]
	ldrb r2, [r4, #6]
	ldrb r3, [r4, #3]

	ldr r5, [sp, #16+12] // roundkey

	bl inv_sbox_addkey_inner_final

	// cleanup
	add sp, #16+16+4

	pop {r0-r3}
	mov r8, r0
	mov r9, r1
	mov r10, r2
	mov r11, r3

	pop {r4-r7, pc}

.balign 4
rcon_reduce:
	movs r5, #0x80 // actually a reduction by 0x8D
	b 1b // continue loop

.balign 4
inv_sbox_addkey_mix_inner:
	// expect extracted elements in r0-r3 (past the shiftrows)
	// roundkey in r5
	// return in r0

	ldrb r0, [r7, r0]
	ldrb r1, [r7, r1]
	ldrb r2, [r7, r2]
	ldrb r3, [r7, r3]

	// pack it
	lsls r1, #8
	orrs r0, r1

	lsls r2, #16
	orrs r0, r2

	lsls r3, #24
	orrs r0, r3

	// addroundkey
	eors r0, r5

	movs r5, #0x1b // has to be temporary due to pressure
	// r6 - 0x01010101

	//expand S{1} to S{2}, S{4}, S{8}
	//all of them have to be preserved

	/* do quad multiplication according to:
	// out = ((in & 0x7f7f7f7f) << 1) ^ (((in & 0x80808080) >> 7)) * 0x1b);

	calculations are modified to perform shifts first to avoid extra moves
	// out = ((in << 1) & 0xfefefefe) ^ (((in >> 7) & 0x01010101) * 0x1b)
	*/

	lsrs r2, r0, #7
	ands r2, r6 // mask
	muls r2, r5 // get predicated reduction

	lsls r1, r0, #1
	bics r1, r6 // & 0xfe

	eors r1, r2 // S{2}

	lsrs r3, r1, #7
	ands r3, r6 // mask
	muls r3, r5 // get predicated reduction

	lsls r2, r1, #1
	bics r2, r6 // & 0xfe

	eors r2, r3 // S{4}

	lsrs r3, r2, #7
	ands r3, r6 // mask
	muls r5, r3 // get predicated reduction

	lsls r3, r2, #1
	bics r3, r6 // & 0xfe

	eors r3, r5 // S{8}

	// r0 - S{1}
	// r1 -	S{2}
	// r2 - S{4}
	// r3 - S{8}
	// r5 -

	eors r0, r3 // S{9}
	eors r3, r1
	eors r3, r2 // S{e}
	eors r1, r0 // S{b}
	eors r2, r0 // S{d}

	// S{9} - ror #24
	// S{b} - ror #8
	// S{d} - ror #16
	// S{e} - ror #0

	movs r5, #24
	rors r0, r5

	eors r0, r3 // s0{e}^s3{9} | s1{e}^s0{9} | s2{e}^s1{9} | s3{e}^s2{9}

	movs r5, #8
	rors r1, r5

	eors r0, r1 // s0{e}^s1{b}^s3{9} | s1{e}^s2{b}^s0{9} | s2{e}^s3{b}^s1{9} | s3{e}^s0{b}^s2{9}

	rev16 r2, r2
	rev r2, r2

	eors r0, r2 // s0{e}^s1{b}^s2{d}^s3{9} | s1{e}^s2{b}^s3{d}^s0{9} | s2{e}^s3{b}^s0{d}^s1{9} | s3{e}^s0{b}^s1{d}^s2{9}

	bx lr

.balign 4
inv_sbox_addkey_inner_final:
	// expect extracted elements in r0-r3 (past the shiftrows)
	// roundkey in r5
	// out ptr in r6 (will be incremented)

	ldrb r0, [r7, r0]
	ldrb r1, [r7, r1]
	ldrb r2, [r7, r2]
	ldrb r3, [r7, r3]

	// pack it
	lsls r1, #8
	orrs r0, r1

	lsls r2, #16
	orrs r0, r2

	lsls r3, #24
	orrs r0, r3

	// addroundkey
	eors r0, r5

	stmia r6!, {r0} // store output

	bx lr

.balign 4
inv_keyschedule:
	// expect pointer to roundkey in r4
	// return rcon in r5
	// rcon is shifted and reduced here, status flags can be used upon return

	// load roundkey, r4 is now free
	ldmia r4!, {r0-r3}

	// undo keyschedule step
	eors r3, r2
	eors r2, r1
	eors r1, r0

	mov r4, r11 // get sbox

	// current allocation
	// r0 - rk[0]
	// r1 - rk[1]`
	// r2 - rk[2]`
	// r3 - rk[3]`
	// r4 - sbox
	// r5 -

	lsrs r5, r3, #8
	uxtb r5, r5
	ldrb r5, [r4, r5]
	eors r0, r5

	lsrs r5, r3, #16
	uxtb r5, r5
	ldrb r5, [r4, r5]
	lsls r5, #8
	eors r0, r5

	lsrs r5, r3, #24
	ldrb r5, [r4, r5]
	lsls r5, #16
	eors r0, r5

	uxtb r5, r3
	ldrb r5, [r4, r5]
	lsls r5, #24
	eors r0, r5

	mov r5, r12 // get rcon

	eors r0, r5 // apply rcon

	// preserve next roundkey
	add r4, sp, #16
	stmia r4!, {r0-r3}

	mov r4, sp // restore r4 for shiftrows

	lsrs r5, #1 // next rcon

	bx lr

#endif
