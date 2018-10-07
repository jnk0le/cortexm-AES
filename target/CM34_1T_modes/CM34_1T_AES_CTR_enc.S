// counter mode, SP 800-38A compliant (32bit, big endian ctr), can start from any counter value
// counter is written back and can be used to continue encryption later

.syntax unified
.thumb
.text

.align 3
// void CM34_1T_CTR_enc(void* ctx, uint8_t* data_in, uint8_t* data_out, uint32_t rounds, uint32_t blocks_cnt) {
.global CM34_1T_AES_CTR_enc
.type   CM34_1T_AES_CTR_enc,%function
CM34_1T_AES_CTR_enc:
	mov r12, r0
	//use this value to reload context pointer before next block encryption
	adds r0, #64 // p+4*4*4

	add r3, r12, r3, lsl #4 //rk_end-16 = rk + rounds * 16
	adds r3, #16 // + nonce

	push {r0-r11,lr} // push ctx+64, data_in, data_out, rk_end-16

	sub sp, #20

	movw r14, #:lower16:AES_Te0
	movt r14, #:upper16:AES_Te0

ctr_partial_precompute:

	//load from ctx nonce in r0-r3, key in r4-r7
	ldmia r12!, {r0-r7}

	//initial addroundkey
	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	//round 1
	uxtb r0, r4 // LE/LEFT
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]

	ldmia r12!, {r8-r11}

	eor r8, r8, r0, ror #16
	eor r9, r9, r1, ror #16
	eor r10, r10, r2, ror #16
	eor r11, r11, r3, ror #16

	uxtb r0, r5, ror #8
	uxtb r1, r6, ror #8
	uxtb r2, r7, ror #8
	uxtb r3, r4, ror #8
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	eor r8, r8, r0, ror #8
	eor r9, r9, r1, ror #8
	eor r10, r10, r2, ror #8
	eor r11, r11, r3, ror #8

	uxtb r0, r6, ror #16
	uxtb r1, r7, ror #16
	uxtb r2, r4, ror #16
	uxtb r3, r5, ror #16

	//uxtb r4, r4, ror #24
	//uxtb r5, r5, ror #24
	lsrs r4, #24
	lsrs r5, #24

	uxtb r6, r6, ror #24 //align to 4 bytes

	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]

	ldr r4, [r14, r4, lsl #2]
	ldr r5, [r14, r5, lsl #2]
	ldr r6, [r14, r6, lsl #2]

	eor r8, r0
	eor r9, r1
	eor r10, r2
	eor r11, r3

	eor r9, r9, r4, ror #24
	eor r10, r10, r5, ror #24
	eor r11, r11, r6, ror #24

	str.w r8, [sp, #16] // precomputed x0

	//round 2
	uxtb r0, r9
	uxtb r1, r10
	uxtb r2, r11

	uxtb r3, r9, ror #8
	uxtb r4, r10, ror #8
	uxtb r5, r11, ror #8

	uxtb r6, r10, ror #16
	uxtb r7, r11, ror #16
	uxtb r8, r9, ror #16

	uxtb r11, r11, ror #24
	uxtb r9, r9, ror #24
	uxtb r10, r10, ror #24

	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]

	ldr r3, [r14, r3, lsl #2]
	ldr r4, [r14, r4, lsl #2]
	ldr r5, [r14, r5, lsl #2]

	ldr r6, [r14, r6, lsl #2]
	ldr r7, [r14, r7, lsl #2]
	ldr r8, [r14, r8, lsl #2]

	ldr r11, [r14, r11, lsl #2]
	ldr r9, [r14, r9, lsl #2]
	ldr r10, [r14, r10, lsl #2]

	//l4 ^=        ^ r3 #8 ^ r6 #0 ^ r11 #24
	//l5 ^= r0 #16 ^ r4 #8 ^ r7 #0
	//l6 ^= r1 #16 ^ r5 #8         ^ r9 #24
	//l7 ^= r2 #16         ^ r8 #0 ^ r10 #24

	//xor intermediate states out of r4-r7

	//t4  #8
	eor r3, r3, r6, ror #24
	eor r3, r3, r11, ror #16

	//t5  #16
	eor r0, r0, r4, ror #24
	eor r0, r0, r7, ror #16

	//t6  #16
	eor r1, r1, r5, ror #24
	eor r1, r1, r9, ror #8

	//t7  #16
	eor r2, r2, r8, ror #16
	eor r2, r2, r10, ror #8

	ldmia r12!, {r4-r7}

	eor r4, r4, r3, ror #8
	eor r5, r5, r0, ror #16
	eor r6, r6, r1, ror #16
	eor r7, r7, r2, ror #16

	//stm sp, {r4-r7}
	str r4, [sp, #0]
	str r5, [sp, #4]
	str r6, [sp, #8]
	str r7, [sp, #12]

	//the first time, we can skip some loads
	b ctr_encrypt_first

.align 3 //align for 8 byte fetching

ctr_encrypt_block: //expect {precomputed_y0..y3, precomputed_x0} on top of stack, p+4*4*4 in r12

	//ldm sp, {r4-r7,r10} //load precomputed
	ldr r4, [sp, #0]
	ldr r5, [sp, #4]
	ldr r6, [sp, #8]
	ldr r7, [sp, #12]

ctr_encrypt_first:
	//load ctr[3]
	ldr r1, [r12, #-52] // -64

	//load key[3]
	ldr r2, [r12, #-36] // -48

	//load precomputed_x0
	ldr r3, [sp, #16]

	//round 1
	eors r1, r2
	uxtb r1, r1, ror #24 // align to 4 bytes
	ldr r1, [r14, r1, lsl #2]
	eor r3, r3, r1, ror #24

	//round 2
	uxtb r0, r3
	//uxtb r1, r3, ror #24
	lsrs r1, r3, #24
	uxtb r2, r3, ror #16
	uxtb r3, r3, ror #8
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	eor r4, r4, r0, ror #16
	eor r5, r5, r1, ror #24
	eor r6, r6, r2
	eor r7, r7, r3, ror #8

1:	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7

	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]

#if __ARM_ARCH_7EM__
	//doesn't pipeline well on cm3
	ldr r8, [r12], #4
	ldr r9, [r12], #4
	ldr r10, [r12], #4
	ldr r11, [r12], #4
#else
	ldmia r12!, {r8-r11}
#endif
	/*ldr r9, [r12, #4]
	ldr r10, [r12, #8]
	ldr r11, [r12, #12]
	ldr r8, [r12], #16*/ // on cm3 same as ldmia

	eor r8, r8, r0, ror #16
	eor r9, r9, r1, ror #16
	eor r10, r10, r2, ror #16
	eor r11, r11, r3, ror #16

	uxtb r0, r5, ror #8
	uxtb r1, r6, ror #8
	uxtb r2, r7, ror #8
	uxtb r3, r4, ror #8
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	eor r8, r8, r0, ror #8
	eor r9, r9, r1, ror #8
	eor r10, r10, r2, ror #8
	eor r11, r11, r3, ror #8

	uxtb r0, r6, ror #16
	uxtb r1, r7, ror #16
	uxtb r2, r4, ror #16
	uxtb r3, r5, ror #16

	//uxtb r7, r7, ror #24
	//uxtb r4, r4, ror #24
	//uxtb r5, r5, ror #24
	//uxtb r6, r6, ror #24
	lsrs r7, #24
	lsrs r4, #24
	lsrs r5, #24
	lsrs r6, #24

	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]

	ldr r7, [r14, r7, lsl #2]
	ldr r4, [r14, r4, lsl #2]
	ldr r5, [r14, r5, lsl #2]
	ldr r6, [r14, r6, lsl #2]

	// change xoring order to writeback r4-r7 without extra moves
	eor r0, r0, r7, ror #24
	eor r1, r1, r4, ror #24

	// set flags early to optimize speculative fetches in cm3
	// cmp have to be close to branch, otherwise speculative code loads doesn't work
	ldr r7, [sp, #32]
	cmp r7, r12

	eor r2, r2, r5, ror #24
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1
	eor r6, r10, r2
	eor r7, r11, r3

	bne.w 1b

	//final round
	uxtb r8, r7, ror #24
	uxtb r9, r4, ror #24
	uxtb r10, r5, ror #24
	uxtb r11, r6, ror #24

	uxtb r0, r6, ror #16
	uxtb r1, r7, ror #16
	uxtb r2, r4, ror #16
	uxtb r3, r5, ror #16

	ldr r8, [r14, r8, lsl #2]
	ldr r9, [r14, r9, lsl #2]
	ldr r10, [r14, r10, lsl #2]
	ldr r11, [r14, r11, lsl #2]

	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]

	bfi r8, r0, #24, #8
	bfi r9, r1, #24, #8
	bfi r10, r2, #24, #8
	bfi r11, r3, #24, #8

	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	bfi r8, r0, #8, #8
	bfi r9, r1, #8, #8
	bfi r10, r2, #8, #8
	bfi r11, r3, #8, #8

	uxtb r0, r5, ror #8
	uxtb r1, r6, ror #8
	uxtb r2, r7, ror #8
	uxtb r3, r4, ror #8
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r4, [r12]
	ldr r5, [r12, #4]
	ldr r6, [r12, #8]
	ldr r7, [r12, #12]

	bfi r8, r0, #16, #8
	bfi r9, r1, #16, #8
	bfi r10, r2, #16, #8
	bfi r11, r3, #16, #8

	//ldmia r12!, {r0-r3}

	eor r8, r4, r8, ror #8
	eor r9, r5, r9, ror #8
	eor r10, r6, r10, ror #8
	eor r11, r7, r11, ror #8

	//load in, out, len counter

	ldr r12, [sp, #20] // reload to p+4*4*4
	ldr r1, [sp, #20+4] // in p
	ldr r2, [sp, #20+8] // out p

#if __ARM_ARCH_7EM__
	ldr r3, [sp, #20+52] // blocks len // argument passed through stack
	ldr r5, [r1, #4]
	// cycle lost if both are moved after ctr load

	ldr r0, [r12, #-52] // ctr
#else
	ldr r0, [r12, #-52] // ctr
	ldr r3, [sp, #20+52] // blocks len // argument passed through stack
#endif

	//load input, xor keystream and write to output
#if __ARM_ARCH_7EM__
	//ldr r5, [r1, #4]
	ldr r6, [r1, #8]
	ldr r7, [r1, #12]
	ldr r4, [r1], #16
#else
	ldmia r1!, {r4-r7}
#endif

	eor r4, r8
	eor r5, r9
	eor r6, r10
	eor r7, r11

	//stmia r2!, {r4-r7}
	str r5, [r2, #4]
	str r6, [r2, #8]
	str r7, [r2, #12]

	rev r0, r0 // waitstate reduction
	adds r0, #1 // also required here, otherwise no yield

	str r4, [r2], #16

	//dec and store len counter // set flags early to optimize speculative fetches in cm3
	subs r3, #1

	rev r0, r0
	str r0, [r12, #-52]

	beq ctr_exit //if len==0: exit

	tst r0, #0xff000000 // set flags early to optimize speculative fetches in cm3
	str r3, [sp, #20+52] // blocks len // argument passed through stack
	str r1, [sp, #20+4] // in p
	str r2, [sp, #20+8] // out p

	bne ctr_encrypt_block //if ctr%256==0: partial_precompute

	sub r12, #64 //reset to p, as required by partial_precompute
	b ctr_partial_precompute

ctr_exit:

	add sp, #20+16
	pop {r4-r11,pc}
