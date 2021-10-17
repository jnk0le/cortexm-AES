// counter mode, SP 800-38A compliant (32bit, big endian ctr), can start from any counter value
// counter is written back and can be used to continue encryption later

// currently requires pointer to ctx struct in form:
//typedef struct {
//    uint8_t nonce[16];
//    uint8_t rk[(n+1)*16];
//} ctx;

.syntax unified
.thumb
.text

.align 3
// void CM7_1T_AES_CTR_enc(void* ctx, uint8_t* data_in, uint8_t* data_out, uint32_t rounds, uint32_t blocks_cnt) {
.global CM7_1T_AES_CTR_enc
.type   CM7_1T_AES_CTR_enc,%function
CM7_1T_AES_CTR_enc:
#if __ARM_ARCH_7M__ || __ARM_ARCH_7EM__
	ldr r12, [sp]
	str lr, [sp, #-4]! // use dead cycles for pushing

	add r3, r0, r3, lsl #4 //rk_end-16 = rk + rounds * 16
	str.w r11, [sp, #-4]!

	pld [r0, #0] // dead cycle anyway, preload anything, cacheline is 32 bytes
	adds r3, #16 // + nonce

	add r12, r1, r12, lsl #4 // in_p + cnt*16
	str r12, [sp, #8]

	mov r12, r0
	adds r0, #64 // p+4*4*4 //use this value to reload context pointer before next block encryption

	push {r1-r10} // push data_in, data_out, rk_end-16

	str r0, [sp, #-4]! //push ctx+64
	movw r14, #:lower16:AES_Te2

	sub sp, #20 // make space for partial precompute
	movt r14, #:upper16:AES_Te2

ctr_partial_precompute:

	//load from ctx nonce in r0-r3, key in r4-r7 + next round in r8-r11
	ldmia r12!, {r0-r11} // leave it as is

	//initial addroundkey
	eors r4, r0
	eors r5, r1

	uxtb r0, r4 // LE/LEFT
	eors r6, r2

	uxtb r1, r5
	eors r7, r3

	//round 1
	uxtb r2, r6
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r7
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #16
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #16
	ldr r3, [r14, r3, lsl #2]

	uxtb r0, r5, ror #8
	eor r10, r10, r2, ror #16

	uxtb r1, r6, ror #8
	eor r11, r11, r3, ror #16

	uxtb r2, r7, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r4, ror #8
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #8
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #8
	ldr r3, [r14, r3, lsl #2]

	uxtb r0, r6, ror #16
	eor r10, r10, r2, ror #8

	uxtb r1, r7, ror #16
	eor r11, r11, r3, ror #8

	uxtb r2, r4, ror #16
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r5, ror #16
	ldr r1, [r14, r1, lsl #2]

	eor r0, r8
	ldr r2, [r14, r2, lsl #2]

	eor r1, r9
	ldr r3, [r14, r3, lsl #2]

	lsr.w r4, r4, #24 // cant .n
	eor r2, r10

	lsr.w r5, r5, #24 // cant .n
	eor r3, r11

	lsr.w r7, r6, #24 // cant .n
	ldr r4, [r14, r4, lsl #2]

	str.w r0, [sp, #16] // precomputed x0 // cant .n
	ldr r6, [r14, r5, lsl #2]

	eor r1, r1, r4, ror #24
	ldr r7, [r14, r7, lsl #2]

	//round 2
	uxtb r5, r1, ror #8
	eor r2, r2, r6, ror #24

	uxtb r4, r2, ror #16
	eor r3, r3, r7, ror #24

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

	uxtb r6, r3, ror #24 // cant .n
	ldr r5, [r14, r5, lsl #2]

	uxtb.w r7, r1 // cant .n
	ldr r4, [r14, r4, lsl #2]

	uxtb r8, r3, ror #16
	ldr r6, [r14, r6, lsl #2]

	uxtb r9, r2, ror #8
	ldr r7, [r14, r7, lsl #2]

	uxtb r10, r2
	eor r4, r4, r5, ror #8 // free up r5

	uxtb r11, r3, ror #8
	ldr r8, [r14, r8, lsl #2]

	uxtb r0, r1, ror #24 // cant .n
	ldr r9, [r14, r9, lsl #2]

	uxtb r3, r3
	ldr r10, [r14, r10, lsl #2]

	uxtb r1, r1, ror #16
	ldr r11, [r14, r11, lsl #2]

	lsrs r2, r2, #24
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
	ldr r5, [r12], #4

	eor r1, r1, r2, ror #24
	ldr r6, [r12], #4

	eor r11, r11, r10, ror #8 //ror 16 into rk
	ldr r7, [r12], #4

	eor r11, r11, r0, ror #16 //ror 24 into rk
	ldr r9, [r12], #4

	eors r5, r4
	eor.w r6, r8

	eor.w r7, r7, r11, ror #8 // finish col2
	str r5, [sp, #0]

	eor.w r1, r9
	str r6, [sp, #4]

	ldr r8, [r12, #-36] //load key[3]
	nop

	ldr r10, [r12, #-52] //preload ctr[3]
	str r7, [sp, #8]

	eor.w r8, r10
	str r1, [sp, #12]

ctr_encrypt_block: //expect {precomputed_y0..y3, precomputed_x0} on top of stack, p+4*4*4 in r12

	//expect ctr[3] in r10
	//expect key[3]^ctr[3] in r8

	lsr.w r8, r8, #24
	ldr r7, [sp, #16] //precomp_x0

	rev.w r9, r10
	ldr r0, [sp, #0]

	add.w r9, #1
	ldr r8, [r14, r8, lsl #2]

	rev.w r9, r9
	ldr r1, [sp, #4]

	eor r8, r7, r8, ror #24
	ldr r2, [sp, #8]

	//round 2
	and.w r4, r8, #0xff
	ldr.w r3, [sp, #12]

	lsr.w r5, r8, #24
	str r9, [r12, #-52]

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

1:	//start extending from the highest byte and load key/loop later
	uxtb r8, r2, ror #16
	lsrs r4, r3, #24

	uxtb r9, r3, ror #16
	lsrs r5, r0, #24

	lsrs r6, r1, #24
	ldr r4, [r14, r4, lsl #2]

	uxtb r10, r0, ror #16
	ldr r8, [r14, r8, lsl #2]

	lsrs r7, r2, #24
	ldr r5, [r14, r5, lsl #2]

	uxtb r11, r1, ror #16
	ldr r9, [r14, r9, lsl #2]

	eor r4, r8, r4, ror #24
	ldr r6, [r14, r6, lsl #2]

	eor r5, r9, r5, ror #24
	ldr r10, [r14, r10, lsl #2]

	//cannot eor yet - so try to free up r0
	// r8 -> r4 ror16
	// r9 -> r7 ror8

	uxtb r9, r0, ror #8
	ldr r7, [r14, r7, lsl #2]

	eor r6, r10, r6, ror #24
	ldr r11, [r14, r11, lsl #2]

	uxtb r8, r0 // and
	ldr r9, [r14, r9, lsl #2]

	eor r7, r11, r7, ror #24
	ldr r0, [r12], #4

	//free up r1
	// r10 -> r5 ror16
	// r11 -> r4 ror8

	uxtb r10, r1
	ldr r8, [r14, r8, lsl #2]

	uxtb r11, r1, ror #8
	ldr r1, [r12], #4

	eor r7, r7, r9, ror #8
	ldr r10, [r14, r10, lsl #2]

	eor r4, r4, r8, ror #16
	ldr r11, [r14, r11, lsl #2]

	// now r2
	// r8 -> r6 ror16
	// r9 -> r5 ror8

	uxtb r8, r2
	eor r5, r5, r10, ror #16

	uxtb r9, r2, ror #8
	ldr r2, [r12], #4

	eor r4, r4, r11, ror #8
	ldr r8, [r14, r8, lsl #2]

	// r3
	// r10 -> r7 ror16
	// r11 -> r6 ror8

	uxtb r10, r3
	ldr r9, [r14, r9, lsl #2]

	uxtb r11, r3, ror #8
	ldr r3, [r12], #4

	eor r6, r6, r8, ror #16
	ldr.w r8, [sp, #32] // we need compare soon // cant .n

	eor r5, r5, r9, ror #8
	ldr r10, [r14, r10, lsl #2]

	cmp.w r8, r12 // cmp at least 3 cycles before branch // cant .n
	ldr r11, [r14, r11, lsl #2]

	eor r7, r7, r10, ror #16
	eor.w r0, r4

	eor r6, r6, r11, ror #8
	eor.w r1, r5

	eor.w r2, r6
	eor.w r3, r7

	nop.w
	bne.w 1b

	//final round

	//recycle final round from DSPsBOX
	//bfi way should be similar

	uxtb r9, r2, ror #16 //row 2 col 0
	lsrs r7, r3, #24 //row 3 col 0 /// .w????

	uxtb r10, r1, ror #8 //row 1 col 0
	and r11, r0, #0xff //row 0 col 0

	lsrs r4, r0, #24 //row 3 col 1 /// .w ????
	ldrb r8, [r14, r7, lsl #2]

	uxtb r5, r3, ror #16
	ldrb r9, [r14, r9, lsl #2]

	uxtb r6, r1 //row 0 col 1
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
	ldr r0, [r12, #0] // column 0 is ready to eor and store

	orr.w r5, r5, r4, lsl #8 // column 1 upper part
	ldrb r8, [r14, r8, lsl #2]

	orr.w r7, r6, r7, lsl #8 //column 1 bottom part
	ldrb r10, [r14, r10, lsl #2]

	orr.w r7, r7, r5, lsl #16 //col 1
	lsrs r4, r1, #24 //row 3 col 2

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

	lsrs r2, r2, #24 //row 3 col 3
	ldrb r6, [r14, r6, lsl #2]

	uxtb r3, r3
	ldrb r5, [r14, r5, lsl #2]

	orr.w r4, r8, r4, lsl #8 // col 2 upper part
	ldrb r9, [r14, r9, lsl #2]

	eor r0, r0, r11 // finish col 0
	ldrb r2, [r14, r2, lsl #2]

	orr.w r5, r6, r5, lsl #8 // col 2 bottom part
	ldrb r3, [r14, r3, lsl #2]

	orr.w r4, r5, r4, lsl #16 // col 2
	ldr r1, [r12, #4] // rk[1]

	//current allocation
	// r0 - finished col 0
	// r1 - rk[1]
	// r2 - row 3 col 3  -> rk[2]
	// r3 - row 0 col 3
	// r4 - col 2
	// r5 -
	// r6 -              -> col 3 upper
	// r7 - col 1
	// r8 -
	// r9 - row 2 col 3  ->
	// r10 - row 1 col 3 -> col 3 bottom
	// r11 -

	orr.w r6, r9, r2, lsl #8 //col 3 upper part
	ldr r2, [r12, #8] // rk[2]

	orr.w r10, r3, r10, lsl #8 // col 3 bottom part
	ldr r3, [r12, #12] // rk[3]

	eors r1, r7
	ldr.w r11, [sp, #20+4] // in p

	orr.w r6, r10, r6, lsl #16 // finish col 3
	ldr.w r10, [sp, #20+52] // final in_p address at which we break encryption // argument passed through stack

	eors r2, r4
	ldr r4, [r11], #4

	eors r3, r6
	ldr r5, [r11], #4

	eors r0, r4
	ldr r6, [r11], #4

	eors r1, r5
	ldr r4, [sp, #20+8] // out p

	eors r2, r6
	ldr r7, [r11], #4

	cmp r10, r11
	str r0, [r4], #4

	ldr r12, [sp, #20] // reload to p+4*4*4
	str r1, [r4], #4

	eor r3, r7
	str r2, [r4], #4

	ldr.w r10, [r12, #-52] // ctr, incremented at the beginning of the loop
	str r3, [r4], #4

	//something is wrong here, cant add single nop anywhere before bne
	beq.w ctr_exit //if in_p == final_p: exit // cant .n

	str r11, [sp, #20+4] // in p
	tst r10, #0xff000000 // sometimes few cycles lost due to branch proximity

	ldr r8, [r12, #-36] // load key[3] //relax the round 1 latency from the beginning of the loop
	str r4, [sp, #20+8] // out p

	eor.w r8, r10 // relax the round 1 latency from the beginning of the loop
	bne.w ctr_encrypt_block //if ctr%256==0: partial_precompute

	sub r12, #64 //reset to p, as required by partial_precompute
	b.w ctr_partial_precompute // cant .n

ctr_exit:
	add sp, #20+16
	pop {r4-r11,pc}
#else
	b . //crash in case the function was called on thumb1 core
#endif
