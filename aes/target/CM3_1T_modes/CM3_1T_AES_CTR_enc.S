// counter mode, SP 800-38A compliant (32bit, big endian ctr), can start from any counter value
// counter is written back and can be used to continue encryption later

.syntax unified
.thumb
.text

.align 3
// void CM3_1T_CTR_enc(void* ctx, uint8_t* data_in, uint8_t* data_out, uint32_t rounds, uint32_t blocks_cnt) {
.global CM3_1T_AES_CTR_enc
.type   CM3_1T_AES_CTR_enc,%function
CM3_1T_AES_CTR_enc:
#if __ARM_ARCH_7M__ || __ARM_ARCH_7EM__
	mov r12, r0
	//use this value to reload context pointer before next block encryption
	adds r0, #64 // 3rd round as common reload point

	add r3, r12, r3, lsl #4 //rk_end-16 = rk + rounds * 16
	adds r3, #16 // + nonce

	push {r0-r11,lr} // push ctx+64, data_in, data_out, rk_end-16

	sub sp, #20

	movw r14, #:lower16:AES_Te2
	movt r14, #:upper16:AES_Te2

	ldr r0, [sp, #20+52]
	add r0, r1, r0, lsl #4 // in_p + cnt*16
	str r0, [sp, #20+52]

	// sp
	// +0  - precomputed_y0
	// +4  - precomputed_y1
	// +8  - precomputed_y2
	// +12 - precomputed_y3
	// +16 - precomputed_x0

	// +20 - ctx+64
	// +24 - data_in
	// +28 - data_out
	// +32 - rk_end-16

	// stacked registers

	// +72 - (blocks_cnt) -> data_end

ctr_partial_precompute:

	//load from ctx nonce in r0-r3, key in r4-r7, next round in r8-r11
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
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]

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

	lsrs r4, #24
	lsrs r5, #24
	uxtb r6, r6, ror #24 // align loads to 4 bytes

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

	ldr r1, [r12, #-52] // preload ctr[3]
	str r4, [sp, #0]
	str r5, [sp, #4]
	str r6, [sp, #8]
	str r7, [sp, #12]

	// the first time, we can skip some loads
	b ctr_encrypt_first

.align 3 // align for 8 byte fetching

ctr_encrypt_block: // expect {precomputed_y0..y3, precomputed_x0} on top of stack, ctx+64 in r12

	ldr r4, [sp, #0]
	ldr r5, [sp, #4]
	ldr r6, [sp, #8]
	ldr r7, [sp, #12]

ctr_encrypt_first:

	// expect ctr[3] in r1

	// load MSB of key[3]
	ldrb r2, [r12, #-36+3]

	// load precomputed_x0
	ldr r3, [sp, #16]

	// rev and inc ctr here
	rev r0, r1
	adds r0, #1

	//round 1
	eor.w r1, r2, r1, lsr #24 // truncate ctr, key is already byte
	rev r0, r0
	ldr r1, [r14, r1, lsl #2]
	str r0, [r12, #-52] // incremented ctr
	eor r3, r3, r1, ror #24

	//round 2
	uxtb r0, r3
	lsrs r1, r3, #24
	uxtb r2, r3, ror #16
	uxtb r3, r3, ror #8
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	eor r4, r4, r0, ror #16
	eor r5, r5, r1, ror #24
	eor r6, r6, r2 // align loop entry
	eor r7, r7, r3, ror #8

1:	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7

#ifdef __ARM_ARCH_7EM__
	// aggregate loads by source in case it lies in different memory blocks
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r9, [r12, #4]
	ldr r10, [r12, #8]
	ldr r11, [r12, #12]
	ldr r8, [r12], #16
#else // cm3 can't post index anywhere but first load
	ldr r8, [r12], #16
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r9, [r12, #-12]
	ldr r10, [r12, #-8]
	ldr r11, [r12, #-4]
#endif

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
	//row 3 - ST3x
	lsrs r0, r7, #24
	lsrs r1, r4, #24
	lsrs r2, r5, #24
	lsrs r3, r6, #24

	//row 2 - ST2x
	uxtb r8, r6, ror #16
	uxtb r9, r7, ror #16
	uxtb r10, r4, ror #16
	uxtb r11, r5, ror #16

	ldrb r0, [r14, r0, lsl #2]
	ldrb r1, [r14, r1, lsl #2]
	ldrb r2, [r14, r2, lsl #2]
	ldrb r3, [r14, r3, lsl #2]

	ldrb r8, [r14, r8, lsl #2]
	ldrb r9, [r14, r9, lsl #2]
	ldrb r10, [r14, r10, lsl #2]
	ldrb r11, [r14, r11, lsl #2]

	//repack upper part (keep in bottom half)
	orr r8, r8, r0, lsl #8
	orr r9, r9, r1, lsl #8
	orr r10, r10, r2, lsl #8
	orr r11, r11, r3, lsl #8

	//row 1 - ST1x
	uxtb r0, r5, ror #8
	uxtb r1, r6, ror #8
	uxtb r2, r7, ror #8
	uxtb r3, r4, ror #8

	//row 0 - ST0x
	uxtb r4, r4
	uxtb r5, r5
	uxtb r6, r6
	uxtb r7, r7

	ldrb r0, [r14, r0, lsl #2]
	ldrb r1, [r14, r1, lsl #2]
	ldrb r2, [r14, r2, lsl #2]
	ldrb r3, [r14, r3, lsl #2]

	ldrb r4, [r14, r4, lsl #2]
	ldrb r5, [r14, r5, lsl #2]
	ldrb r6, [r14, r6, lsl #2]
	ldrb r7, [r14, r7, lsl #2]

	//repack bottom part
	orr r4, r4, r0, lsl #8
	orr r5, r5, r1, lsl #8
	orr r6, r6, r2, lsl #8
	orr r7, r7, r3, lsl #8

	ldr r0, [r12]
	ldr r1, [r12, #4]
	ldr r2, [r12, #8]
	ldr r3, [r12, #12]

	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	//repack wholly // bottom is xor'd with rk
	eor r8, r4, r8, lsl #16
	eor r9, r5, r9, lsl #16
	eor r10, r6, r10, lsl #16
	eor r11, r7, r11, lsl #16

	//load in, out, len counter
	ldr r12, [sp, #20] // reload to ctx+64
	ldr r0, [sp, #20+4] // in p
	ldr r2, [sp, #20+8] // out p
	ldr r3, [sp, #20+52] // final in_p address at which we break encryption  // argument passed through stack

	//load input, xor keystream and write to output
#if __ARM_ARCH_7EM__
	ldr r5, [r0, #4]
	ldr r6, [r0, #8]
	ldr r7, [r0, #12]
	ldr r4, [r0], #16
#else
	ldmia r0!, {r4-r7} // cm3 can't post index anywhere but first load
#endif

	eor r4, r8
	eor r5, r9
	eor r6, r10
	eor r7, r11

	cmp r3, r0 // set flags early to optimize speculative fetches in cm3

	str r5, [r2, #4]
	str r6, [r2, #8]
	str r7, [r2, #12]
	str r4, [r2], #16 // cm3?

	beq ctr_exit // if in_p == final_p: exit

	ldr r1, [r12, #-52] // ctr, incremented at the beginning of the loop
	str r0, [sp, #20+4] // in p

	tst r1, #0xff000000 // set flags early to optimize speculative fetches in cm3
	str r2, [sp, #20+8] // out p

	bne ctr_encrypt_block
	//if ctr%256==0: partial_precompute

	sub r12, #64 //reset to p, as required by partial_precompute
	b ctr_partial_precompute

ctr_exit:
	add sp, #20+16
	pop {r4-r11,pc}
#else
	b . //crash in case the function was called on thumb1 core
#endif
