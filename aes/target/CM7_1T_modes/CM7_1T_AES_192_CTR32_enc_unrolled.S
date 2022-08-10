/*!
 * \file CM7_1T_AES_192_CTR32_enc_unrolled.S
 * \brief
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 * \date 30 sep 2018
 */

// counter mode, SP 800-38A compliant (32bit, big endian ctr), can start from any counter value
// counter is written back and can be used to continue encryption later

// currently requires pointer to ctx struct in form:
//typedef struct {
//    uint8_t nonce[16];
//    uint8_t rk[(n+1)*16];
//} ctx;

.include "aes/target/CM7_1T/CM7_1T_AES_common.inc"

.syntax unified
.thumb
.text

.align 3
// void CM7_1T_AES_192_CTR32_enc_unrolled(void* ctx, uint8_t* data_in, uint8_t* data_out, uint32_t blocks_cnt) {
.global CM7_1T_AES_192_CTR32_enc_unrolled
.type   CM7_1T_AES_192_CTR32_enc_unrolled,%function
CM7_1T_AES_192_CTR32_enc_unrolled:
#if __ARM_ARCH_7EM__
	pld [r0, #0] // dead cycle anyway, preload anything, cacheline is 32 bytes
	add r3, r1, r3, lsl #4 // in_p + cnt*16

	push {r1-r11,lr} // push data_in, data_out, blocks_cnt

	mov.w r12, r0
	sub.w sp, #20

	movw r14, #:lower16:AES_Te2
	movt r14, #:upper16:AES_Te2

ctr_partial_precompute:
	//load from ctx nonce in r0-r3, key in r4-r7 + next round in r8-r11
	ldm r12, {r0-r11}

	//initial addroundkey
	eor.w r0, r4
	eor.w r1, r5

	uxtb.w r4, r0 // LE/LEFT
	eor.w r2, r6

	uxtb.w r5, r1
	eor.w r3, r7

	//round 1
uxtb.w r6, r2
	ldr r4, [r14, r4, lsl #2]

	uxtb.w r7, r3
	ldr r5, [r14, r5, lsl #2]

	eor r8, r8, r4, ror #16
	ldr r6, [r14, r6, lsl #2]

	eor r9, r9, r5, ror #16
	ldr r7, [r14, r7, lsl #2]

	uxtb.w r4, r1, ror #8
	eor r10, r10, r6, ror #16

	uxtb.w r5, r2, ror #8
	eor r11, r11, r7, ror #16

	uxtb.w r6, r3, ror #8
	ldr r4, [r14, r4, lsl #2]

	uxtb.w r7, r0, ror #8
	ldr r5, [r14, r5, lsl #2]

	eor r8, r8, r4, ror #8
	ldr r6, [r14, r6, lsl #2]

	eor r9, r9, r5, ror #8
	ldr r7, [r14, r7, lsl #2]

	uxtb.w r4, r2, ror #16
	eor r10, r10, r6, ror #8

	uxtb.w r5, r3, ror #16
	eor r11, r11, r7, ror #8

	uxtb.w r6, r0, ror #16
	ldr r4, [r14, r4, lsl #2]

	uxtb.w r7, r1, ror #16
	ldr r5, [r14, r5, lsl #2]

	eor r8, r4 // precomputed x0 // r3>>24 is ctr
	ldr r6, [r14, r6, lsl #2]

	eor r9, r5
	ldr r7, [r14, r7, lsl #2]

	lsr.w r4, r0, #24
	eor r10, r6

	lsr.w r6, r1, #24
	eor r11, r7 // can write r3 now

	lsr.w r7, r2, #24
	ldr r4, [r14, r4, lsl #2]

	str.w r8, [sp, #16] // store precomputed x0
	ldr r6, [r14, r6, lsl #2]

	eor r1, r9, r4, ror #24
	ldr r7, [r14, r7, lsl #2]

	//round 2 // columns 1-3 only
	uxtb r5, r1, ror #8
	eor r2, r10, r6, ror #24

	uxtb r4, r2, ror #16
	eor r3, r11, r7, ror #24

	//extend from col 1-3 in r1-r3
	// prepare columns to eor with rk //////////2x uxtb instead of eor mid?????????
	//
	// r0 - C2 - uxtb24 -> eor24
	// r1 - C3 - uxtb16 -> eor0 // ??
	// r2 - C3 - uxtb24 -> eor24 // ??
	// r3 - C3 - uxtb -> eor16 // ??
	// r4 - C0 - uxtb16 -> eor0
	// r5 - C0 - uxtb8 -> eor8 // eor mid extending
	// r6 - C0 - uxtb24 -> eor24
	// r7 - C1 - uxtb0 -> eor16
	// r8 - C1 - uxtb16 -> eor0
	// r9 - C1 - uxtb8 -> eor8
	// r10 - C2 - uxtb -> eor16
	// r11 - C2 - uxtb8 -> eor8

	uxtb r6, r3, ror #24
	ldr r5, [r14, r5, lsl #2]

	uxtb.w r7, r1
	ldr r4, [r14, r4, lsl #2]

	uxtb r8, r3, ror #16
	ldr r6, [r14, r6, lsl #2]

	uxtb r9, r2, ror #8
	ldr r7, [r14, r7, lsl #2]

	uxtb r10, r2
	eor r4, r4, r5, ror #8 // free up r5

	uxtb r11, r3, ror #8
	ldr r8, [r14, r8, lsl #2]

	uxtb r0, r1, ror #24
	ldr r9, [r14, r9, lsl #2]

	uxtb.w r3, r3
	ldr r10, [r14, r10, lsl #2]

	uxtb r1, r1, ror #16
	ldr r11, [r14, r11, lsl #2]

	lsr.w r2, r2, #24
	ldr r0, [r14, r0, lsl #2]

	// col0 - r4 rk[0] - r5
	// col1 - r8 rk[1] - r6
	// col2 - r11(ror8) rk[2] - r7
	// col3 - r1 rk[3] - r9

	eor r4, r4, r6, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r8, r8, r7, ror #16
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r9, ror #8
	ldr r2, [r14, r2, lsl #2]

	eor r1, r1, r3, ror #16
	ldr r5, [r12, #48]

	eor r1, r1, r2, ror #24
	ldr r6, [r12, #52]

	eor r11, r11, r10, ror #8 //ror 16 into rk
	ldr r7, [r12, #56]

	eor r11, r11, r0, ror #16 //ror 24 into rk
	ldr r9, [r12, #60]

	eor.w r5, r4
	eor.w r6, r8

	eor.w r7, r7, r11, ror #8 // finish col2
	str.w r5, [sp, #0]

	eor.w r1, r9
	str.w r6, [sp, #4]

	ldr r8, [r12, #28] //preload key[3]
	nop.w //wasted???

	ldr r10, [r12, #12] //preload ctr[3]
	str.w r7, [sp, #8]

	eor.w r8, r10
	str.w r1, [sp, #12]

	//.align 3
ctr_encrypt_block:
	//expect {precomputed_y0..y3, precomputed_x0} on top of stack
	//expect ctr[3] in r10
	//expect key[3]^ctr[3] in r8
	//expect r12 pointing at beginning of ctx

	//round 1
	lsr.w r8, r8, #24
	ldr.w r7, [sp, #16] //precomp_x0

	rev.w r9, r10
	ldr.w r0, [sp, #0] //precomp_y0

	add.w r9, #1
	ldr r8, [r14, r8, lsl #2]

	rev.w r9, r9
	ldr.w r1, [sp, #4] // precomp_y1

	eor r8, r7, r8, ror #24
	ldr.w r2, [sp, #8] // precomp_y2

	//round 2
	and.w r4, r8, #0xff
	str r9, [r12, #12] // store ctr back

	lsr.w r5, r8, #24
	ldr.w r3, [sp, #12]

	uxtb r7, r8, ror #8
	ldr r4, [r14, r4, lsl #2]

	uxtb r6, r8, ror #16
	ldr r5, [r14, r5, lsl #2]

	eor r0, r0, r4, ror #16
	ldr r7, [r14, r7, lsl #2]

	eor r1, r1, r5, ror #24
	ldr r6, [r14, r6, lsl #2]

	eor r3, r3, r7, ror #8
	eor r2, r2, r6

	CM7_1T_unrolled_enc_round_n 3, 16
	CM7_1T_unrolled_enc_round_n 4, 16
	CM7_1T_unrolled_enc_round_n 5, 16
	CM7_1T_unrolled_enc_round_n 6, 16
	CM7_1T_unrolled_enc_round_n 7, 16
	CM7_1T_unrolled_enc_round_n 8, 16
	CM7_1T_unrolled_enc_round_n 9, 16
	CM7_1T_unrolled_enc_round_n 10, 16
	CM7_1T_unrolled_enc_round_n 11, 16

	//final round

	//recycle final round from DSPsBOX
	//bfi way should be similar

	uxtb r9, r2, ror #16 //row 2 col 0
	lsr.w r7, r3, #24 //row 3 col 0

	uxtb r10, r1, ror #8 //row 1 col 0
	and r11, r0, #0xff //row 0 col 0

	lsr.w r4, r0, #24 //row 3 col 1
	ldrb r8, [r14, r7, lsl #2]

	uxtb r5, r3, ror #16
	ldrb r9, [r14, r9, lsl #2]

	uxtb.w r6, r1 //row 0 col 1
	ldrb r10, [r14, r10, lsl #2]

	uxtb r7, r2, ror #8 //row 1 col 1
	ldrb r11, [r14, r11, lsl #2]

	orr.w r9, r9, r8, lsl #8 // column 0 upper part
	ldrb r4, [r14, r4, lsl #2]

	uxtb r8, r0, ror #16 //row 2 col 2
	ldrb r5, [r14, r5, lsl #2]

	orr.w r11, r11, r10, lsl #8 // column 0 bottom part
	ldrb r6, [r14, r6, lsl #2]

	uxtb r10, r0, ror #8 //row 1 col 3
	ldrb r7, [r14, r7, lsl #2]

	orr.w r11, r11, r9, lsl #16 // col 0
	ldr r0, [r12, #208] // column 0 is ready to eor and store

	orr.w r5, r5, r4, lsl #8 // column 1 upper part
	ldrb r8, [r14, r8, lsl #2]

	orr.w r7, r6, r7, lsl #8 //column 1 bottom part
	ldrb r10, [r14, r10, lsl #2]

	orr.w r7, r7, r5, lsl #16 //col 1
	lsr.w r4, r1, #24 //row 3 col 2

	uxtb r5, r3, ror #8 //row 1 col 2
	and.w r6, r2, 0xff //row 0 col 2

	//current allocation
	// r0 - rk[0]
	// r1 - old col 1
	// r2 - old col 2
	// r3 - old col 3
	// r4 - (row 3 col 2)
	// r5 - (row 1 col 2)
	// r6 - (row 0 col 2)
	// r7 - col 1
	// r8 - row 2 col 2
	// r9 -
	// r10 - row 1 col 3
	// r11 - col 0

	uxtb r9, r1, ror #16 //row 2 col 3
	ldrb r4, [r14, r4, lsl #2]

	lsr.w r2, r2, #24 //row 3 col 3
	ldrb r6, [r14, r6, lsl #2]

	uxtb.w r3, r3
	ldrb r5, [r14, r5, lsl #2]

	orr.w r4, r8, r4, lsl #8 // col 2 upper part
	ldrb r9, [r14, r9, lsl #2]

	eor r0, r0, r11 // finish col 0
	ldrb r2, [r14, r2, lsl #2]

	orr.w r5, r6, r5, lsl #8 // col 2 bottom part
	ldr.w r6, [sp, #20] // in p // cant use next cycle // ldmia doesn't work well, ldrd is too much hassle

	orr.w r4, r5, r4, lsl #16 // col 2
	ldrb r3, [r14, r3, lsl #2]

	//current allocation
	// r0 - finished col 0
	// r1 -
	// r2 - row 3 col 3  -> input 0
	// r3 - row 0 col 3  -> input 1
	// r4 - col 2
	// r5 -
	// r6 - in p
	// r7 - col 1
	// r8 -
	// r9 - row 2 col 3  ->
	// r10 - row 1 col 3 -> col 3 bottom
	// r11 -             -> col 3 upper

	orr.w r11, r9, r2, lsl #8 //col 3 upper part
	ldr r2, [r6], #4

	orr.w r10, r3, r10, lsl #8 // col 3 bottom part
	ldr r3, [r6], #4

	//current allocation
	// r0 - finished col 0 -> output 0
	// r1 -                -> x
	// r2 - input 0        -> input 2 -> input 2 ^ col 2
	// r3 - input 1
	// r4 - col 2          -> col 3
	// r5 -                -> input 3
	// r6 - in p
	// r7 - col 1
	// r8 -
	// r9 -
	// r10 - col 3 bottom
	// r11 - col 3 upper

	eor.w r0, r2
	ldr r2, [r6], #4

	eor.w r2, r4
	ldr r5, [r6], #4

	orr.w r4, r10, r11, lsl #16 // finish col 3
	ldr.w r1, [sp, #20+8] // final in_p address at which we break encryption

	//current allocation
	// r0 - output 0
	// r1 - final in p      -> rk[1] -> finished col 1 -> output 1
	// r2 - input 2 ^ col 2
	// r3 - input 1         -> rk[3]
	// r4 - col 3           -> out p
	// r5 - input 3
	// r6 - in p
	// r7 - col 1           -> rk[2]
	// r8 -
	// r9 -
	// r10 -
	// r11 -

	cmp.w r1, r6 // cmp at least 3 cycles ahead
	ldr.w r1, [r12, #212] // rk[1]

	eor.w r1, r7
	ldr.w r7, [r12, #216] // rk[2]

	eor.w r1, r3
	ldr.w r3, [r12, #220] // rk[3]

	eor.w r5, r4
	ldr.w r4, [sp, #20+4] // out p

	//current allocation
	// r0 - output 0
	// r1 - output 1
	// r2 - input 2 ^ col 2   -> output 2
	// r3 - rk[3]             -> output 3
	// r4 - out p
	// r5 - col 3 ^ input 3
	// r6 - in p
	// r7 - rk[2]
	// r8 -                   -> key[3]
	// r9 -
	// r10 -                  -> ctr
	// r11 -

	eor.w r2, r7
	ldr r10, [r12, #12] // ctr, incremented at the beginning of the loop         // r10

	eor.w r3, r5
	beq.w ctr_exit //if in_p == final_p: exit

	str.w r6, [sp, #20] // in p
	tst r10, #0xff000000 // set flags early

	strd r0,r1, [r4], #8

	str.w r2, [r4], #4
	ldr r8, [r12, #28] // preload key[3] //relax the round 1 latency from the beginning of the loop

	str.w r3, [r4], #4
	eor.w r8, r10 // relax the round 1 latency from the beginning of the loop

	//strd #16

	str.w r4, [sp, #20+4] // out p
	bne.w ctr_encrypt_block //if (BE)ctr%256!=0

	//nop.w // align exit point
	b.w ctr_partial_precompute

ctr_exit:
	add sp, #20+12
	stmia r4!, {r0-r3} // store last block
	pop {r4-r11,pc}
#else
	b . //crash in case the function was called on thumb1 core
#endif
