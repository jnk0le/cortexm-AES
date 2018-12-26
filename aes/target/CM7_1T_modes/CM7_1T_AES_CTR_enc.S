// counter mode, SP 800-38A compliant (32bit, big endian ctr), can start from any counter value
// counter is written back and can be used to continue encryption later

.syntax unified
.thumb
.text

.align 3
// void CM7_1T_AES_CTR_enc(void* ctx, uint8_t* data_in, uint8_t* data_out, uint32_t rounds, uint32_t blocks_cnt) {
.global CM7_1T_AES_CTR_enc
.type   CM7_1T_AES_CTR_enc,%function
CM7_1T_AES_CTR_enc:
	ldr r12, [sp]
	nop.w

	add r12, r1, r12, lsl #4 // in_p + cnt*16
	str r12, [sp]

	mov r12, r0
	add r3, r12, r3, lsl #4 //rk_end-16 = rk + rounds * 16

	//use this value to reload context pointer before next block encryption
	adds r0, #64 // p+4*4*4
	adds r3, #16 // + nonce

	push {r1-r11,lr} // push data_in, data_out, rk_end-16

	str r0, [sp, #-4]! //push ctx+64
	movw r14, #:lower16:AES_Te0

	sub sp, #20
	movt r14, #:upper16:AES_Te0

ctr_partial_precompute:

	//load from ctx nonce in r0-r3, key in r4-r7 + next round in r8-r11
	ldmia r12!, {r0-r11}

	//initial addroundkey
	eors r4, r0
	eors r5, r1

	eors r6, r2
	eors r7, r3

	//round 1
	uxtb r0, r4 // LE/LEFT
	uxtb r1, r5

	uxtb r2, r6
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r7
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #16
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #16
	ldr r3, [r14, r3, lsl #2]

	eor r10, r10, r2, ror #16
	uxtb r0, r5, ror #8

	eor r11, r11, r3, ror #16
	uxtb r1, r6, ror #8

	uxtb r2, r7, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r4, ror #8
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #8
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #8
	ldr r3, [r14, r3, lsl #2]

	eor r10, r10, r2, ror #8
	uxtb r0, r6, ror #16

	eor r11, r11, r3, ror #8
	uxtb r1, r7, ror #16

	uxtb r2, r4, ror #16
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r5, ror #16
	ldr r1, [r14, r1, lsl #2]

	uxtb r4, r4, ror #24
	ldr r2, [r14, r2, lsl #2]

	uxtb r5, r5, ror #24
	ldr r3, [r14, r3, lsl #2]

	uxtb r6, r6, ror #24
	ldr r4, [r14, r4, lsl #2]

	eor r8, r0
	ldr r5, [r14, r5, lsl #2]

	eor r9, r1
	ldr r6, [r14, r6, lsl #2]

	eor r10, r2
	eor r11, r3

	str.w r8, [sp, #16] // precomputed x0
	eor r9, r9, r4, ror #24

	eor r10, r10, r5, ror #24
	eor r11, r11, r6, ror #24

	//round 2
	uxtb r0, r9
	uxtb r1, r10

	uxtb r2, r11
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r9, ror #8
	ldr r1, [r14, r1, lsl #2]

	uxtb r4, r10, ror #8
	ldr r2, [r14, r2, lsl #2]

	uxtb r5, r11, ror #8
	ldr r3, [r14, r3, lsl #2]

	uxtb r6, r10, ror #16
	ldr r4, [r14, r4, lsl #2]

	uxtb r7, r11, ror #16
	ldr r5, [r14, r5, lsl #2]

	uxtb r8, r9, ror #16
	ldr r6, [r14, r6, lsl #2]

	uxtb r11, r11, ror #24
	ldr r7, [r14, r7, lsl #2]

	uxtb r9, r9, ror #24
	ldr r8, [r14, r8, lsl #2]

	uxtb r10, r10, ror #24
	ldr r11, [r14, r11, lsl #2]

	//l4 ^=        ^ r3 #8 ^ r6 #0 ^ r11 #24
	//l5 ^= r0 #16 ^ r4 #8 ^ r7 #0
	//l6 ^= r1 #16 ^ r5 #8         ^ r9 #24
	//l7 ^= r2 #16         ^ r8 #0 ^ r10 #24

	//xor intermediate states out of r4-r7

	//r3 - t4  #8
	//r0 - t5  #16
	//r1 - t6  #16
	//r2 - t7  #16

	eor r3, r3, r6, ror #24
	ldr r9, [r14, r9, lsl #2]

	eor r0, r0, r4, ror #24
	ldr r10, [r14, r10, lsl #2]

	eor r3, r3, r11, ror #16
	eor r0, r0, r7, ror #16

	eor r1, r1, r5, ror #24
	eor r2, r2, r8, ror #16

	eor r1, r1, r9, ror #8
	eor r2, r2, r10, ror #8

	ldmia r12!, {r4-r7}

	eor r4, r4, r3, ror #8
	eor r5, r5, r0, ror #16

	eor r6, r6, r1, ror #16
	eor r7, r7, r2, ror #16

	stm sp, {r4-r7}

	//.align 3

ctr_encrypt_block: //expect {precomputed_y0..y3, precomputed_x0} on top of stack, p+4*4*4 in r12
	// there is so much stalling that we have no reason to do load skipping

	//load ctr[3]
	ldr r1, [r12, #-52]
	nop // r1 is not available here

	//load key[3]
	ldr r2, [r12, #-36]
	rev r0, r1

	//load precomputed_x0
	ldr r3, [sp, #16]
	//round 1
	eors r1, r2

	ldr r4, [sp, #0]
	uxtb r1, r1, ror #24
	//lsr.w r1, r1, #24 // no diff if dependent ldr is older opcode

	adds r0, #1 // cycle lost if adds is older opcode even with lsr workaround
	ldr r1, [r14, r1, lsl #2]

	rev r0, r0
	str r0, [r12, #-52]

	ldr r5, [sp, #4]
	ldr r6, [sp, #8]

	eor r3, r3, r1, ror #24
	ldr r7, [sp, #12]

	//round 2
	uxtb.w r0, r3
	uxtb r1, r3, ror #24

	uxtb r2, r3, ror #16
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r3, ror #8
	ldr r1, [r14, r1, lsl #2]

	eor r4, r4, r0, ror #16
	ldr r2, [r14, r2, lsl #2]

	eor r5, r5, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r6, r2
	eor r7, r7, r3, ror #8

	//8 + 4 alignment required here
1:	//ldmia r12!, {r8-r11}
	ldrd r8,r9, [r12], #8

	uxtb r0, r4
	ldr r10, [r12], #4

	uxtb r1, r5
	ldr r11, [r12], #4

	uxtb r2, r6
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r7
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #16
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #16
	ldr r3, [r14, r3, lsl #2]

	eor r10, r10, r2, ror #16
	eor r11, r11, r3, ror #16

	uxtb r0, r5, ror #8
	uxtb r1, r6, ror #8

	uxtb r2, r7, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r4, ror #8
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #8
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #8
	ldr r3, [r14, r3, lsl #2]

	eor r10, r10, r2, ror #8
	uxtb r0, r6, ror #16

	eor r11, r11, r3, ror #8
	uxtb r1, r7, ror #16

	uxtb r2, r4, ror #16
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r5, ror #16
	ldr r1, [r14, r1, lsl #2]

	uxtb r7, r7, ror #24
	ldr r2, [r14, r2, lsl #2]

	uxtb r4, r4, ror #24
	ldr r3, [r14, r3, lsl #2]

	uxtb r5, r5, ror #24
	ldr r7, [r14, r7, lsl #2]

	uxtb r6, r6, ror #24
	ldr r4, [r14, r4, lsl #2]

	// change xoring order to writeback r4-r7 without extra moves
	eor r0, r0, r7, ror #24
	ldr r5, [r14, r5, lsl #2]

	eor r1, r1, r4, ror #24
	ldr r6, [r14, r6, lsl #2]

	eor r2, r2, r5, ror #24
	ldr r7, [sp, #32] // assume inherited delay from register offset ldr

	eor r3, r3, r6, ror #24
	eor r4, r8, r0

	cmp r7, r12
	eor r5, r9, r1

	eor r6, r10, r2
	eor r7, r11, r3

	nop //
	bne 1b

	//final round
	uxtb r8, r7, ror #24
	uxtb r9, r4, ror #24

	uxtb r10, r5, ror #24
	ldr r8, [r14, r8, lsl #2]

	uxtb r11, r6, ror #24
	ldr r9, [r14, r9, lsl #2]

	uxtb r0, r6, ror #16
	ldr r10, [r14, r10, lsl #2]

	uxtb r1, r7, ror #16
	ldr r11, [r14, r11, lsl #2]

	uxtb r2, r4, ror #16
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r5, ror #16
	ldr r1, [r14, r1, lsl #2]

	bfi r8, r0, #24, #8
	ldr r2, [r14, r2, lsl #2]

	bfi r9, r1, #24, #8
	ldr r3, [r14, r3, lsl #2]

	bfi r10, r2, #24, #8
	uxtb r0, r4

	bfi r11, r3, #24, #8
	uxtb r1, r5

	uxtb r2, r6
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r7
	ldr r1, [r14, r1, lsl #2]

	bfi r8, r0, #8, #8
	ldr r2, [r14, r2, lsl #2]

	bfi r9, r1, #8, #8
	ldr r3, [r14, r3, lsl #2]

	bfi r10, r2, #8, #8
	uxtb r0, r5, ror #8

	bfi r11, r3, #8, #8
	uxtb r1, r6, ror #8

	uxtb r2, r7, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r4, ror #8
	ldr r1, [r14, r1, lsl #2]

	bfi r8, r0, #16, #8
	ldr r2, [r14, r2, lsl #2]

	bfi r9, r1, #16, #8
	ldr r3, [r14, r3, lsl #2]

	//ldmia r12!, {r4-r7}
	ldr r4, [r12]
	ldr r5, [r12, #4]

	ldr r6, [r12, #8]
	ldr r7, [r12, #12]

	bfi r10, r2, #16, #8
	ldr r12, [sp, #20] // reload to p+4*4*4

	bfi r11, r3, #16, #8
	ldr r1, [sp, #20+4] // in p

	eor r8, r4, r8, ror #8
	ldr r3, [sp, #20+52] // final in_p address at which we break encryption // argument passed through stack

	eor r9, r5, r9, ror #8
	ldr r2, [sp, #20+8] // out p

	eor r10, r6, r10, ror #8
	ldr r0, [r12, #-52] // ctr, incremented at the beginning of the loop

	eor r11, r7, r11, ror #8
	ldr r4, [r1], #4

	eor r4, r8
	ldr r5, [r1], #4

	eor r5, r9
	ldr r6, [r1], #4

	eor r6, r10
	ldr r7, [r1], #4

	eor r7, r11
	cmp r3, r1

	stmia r2!, {r4-r7}

	beq ctr_exit //if in_p == final_p: exit
	//str r3, [sp, #20+52] // blocks len // argument passed through stack
	tst r0, #0xff000000 // set flags early

	//str r1, [sp, #20+4] // in p
	//str r2, [sp, #20+8] // out p

	strd r1,r2, [sp, #20+4] // in and out

	bne ctr_encrypt_block //if ctr%256==0: partial_precompute
	sub r12, #64 //reset to p, as required by partial_precompute

	b ctr_partial_precompute

ctr_exit:

	add sp, #20+16
	pop {r4-r11,pc}
