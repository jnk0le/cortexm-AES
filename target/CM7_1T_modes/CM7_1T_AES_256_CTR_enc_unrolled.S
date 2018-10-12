// counter mode, SP 800-38A compliant (32bit, big endian ctr), can start from any counter value
// counter is written back and can be used to continue encryption later

.syntax unified
.thumb
.text

.align 3
// void CM7_1T_AES_256_CTR_enc_unrolled(void* ctx, uint8_t* data_in, uint8_t* data_out, uint32_t rounds, uint32_t blocks_cnt) {
.global CM7_1T_AES_256_CTR_enc_unrolled
.type   CM7_1T_AES_256_CTR_enc_unrolled,%function
CM7_1T_AES_256_CTR_enc_unrolled:
	add r3, r1, r3, lsl #4 // in_p + cnt*16
	nop.w

	push {r1-r11,lr} // push data_in, data_out, blocks_cnt

	mov r12, r0
	sub sp, #20

	movw r14, #:lower16:AES_Te0
	movt r14, #:upper16:AES_Te0

ctr_partial_precompute:
	//load from ctx nonce in r0-r3, key in r4-r7 + next round in r8-r11
	ldm r12, {r0-r11}

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
	ldr r4, [r12, #48]

	eor r2, r2, r8, ror #16
	ldr r5, [r12, #52]

	eor r1, r1, r9, ror #8
	ldr r6, [r12, #56]

	eor r2, r2, r10, ror #8
	ldr r7, [r12, #60]

	eor r4, r4, r3, ror #8
	eor r5, r5, r0, ror #16

	eor r6, r6, r1, ror #16
	eor r7, r7, r2, ror #16

	stm sp, {r4-r7}

	//.align 3

ctr_encrypt_block: //expect {precomputed_y0..y3, precomputed_x0} on top of stack, p+4*4*4 in r12
	// there is so much stalling that we have no reason to do load skipping

	//load ctr[3]
	ldr r1, [r12, #12]
	nop  // r1 is not available here

	//load key[3]
	ldr r2, [r12, #28]
	rev r0, r1

	//load precomputed_x0
	ldr r3, [sp, #16]
	//round 1
	eors r1, r2

	uxtb r1, r1, ror #24
	//lsr.w r1, r1, #24
	ldr r4, [sp, #0]

	adds r0, #1
	ldr r1, [r14, r1, lsl #2]

	rev r0, r0
	str r0, [r12, #12]

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
	ldr r8, [r12, #64]

	eor r7, r7, r3, ror #8
	ldr r9, [r12, #68]

	//round 3
	uxtb r0, r4
	ldr r10, [r12, #72]

	uxtb r1, r5
	ldr r11, [r12, #76]

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
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1

	eor r6, r10, r2
	ldr r8, [r12, #80]

	eor r7, r11, r3
	ldr r9, [r12, #84]

	//round 4
	uxtb r0, r4
	ldr r10, [r12, #88]

	uxtb r1, r5
	ldr r11, [r12, #92]

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
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1

	eor r6, r10, r2
	ldr r8, [r12, #96]

	eor r7, r11, r3
	ldr r9, [r12, #100]

	//round 5
	uxtb r0, r4
	ldr r10, [r12, #104]

	uxtb r1, r5
	ldr r11, [r12, #108]

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
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1

	eor r6, r10, r2
	ldr r8, [r12, #112]

	eor r7, r11, r3
	ldr r9, [r12, #116]

	//round 6
	uxtb r0, r4
	ldr r10, [r12, #120]

	uxtb r1, r5
	ldr r11, [r12, #124]

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
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1

	eor r6, r10, r2
	ldr r8, [r12, #128]

	eor r7, r11, r3
	ldr r9, [r12, #132]

	//round 7
	uxtb r0, r4
	ldr r10, [r12, #136]

	uxtb r1, r5
	ldr r11, [r12, #140]

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
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1

	eor r6, r10, r2
	ldr r8, [r12, #144]

	eor r7, r11, r3
	ldr r9, [r12, #148]

	//round 8
	uxtb r0, r4
	ldr r10, [r12, #152]

	uxtb r1, r5
	ldr r11, [r12, #156]

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
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1

	eor r6, r10, r2
	ldr r8, [r12, #160]

	eor r7, r11, r3
	ldr r9, [r12, #164]

	//round 9
	uxtb r0, r4
	ldr r10, [r12, #168]

	uxtb r1, r5
	ldr r11, [r12, #172]

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
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1

	eor r6, r10, r2
	ldr r8, [r12, #176]

	eor r7, r11, r3
	ldr r9, [r12, #180]

	//round 10
	uxtb r0, r4
	ldr r10, [r12, #184]

	uxtb r1, r5
	ldr r11, [r12, #188]

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
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1

	eor r6, r10, r2
	ldr r8, [r12, #192]

	eor r7, r11, r3
	ldr r9, [r12, #196]

	//round 11
	uxtb r0, r4
	ldr r10, [r12, #200]

	uxtb r1, r5
	ldr r11, [r12, #204]

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
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1

	eor r6, r10, r2
	ldr r8, [r12, #208]

	eor r7, r11, r3
	ldr r9, [r12, #212]

	//round 12
	uxtb r0, r4
	ldr r10, [r12, #216]

	uxtb r1, r5
	ldr r11, [r12, #220]

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
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1

	eor r6, r10, r2
	ldr r8, [r12, #224]

	eor r7, r11, r3
	ldr r9, [r12, #228]

	//round 13
	uxtb r0, r4
	ldr r10, [r12, #232]

	uxtb r1, r5
	ldr r11, [r12, #236]

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
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1

	eor r6, r10, r2
	eor r7, r11, r3

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

	ldr r4, [r12, #240]
	ldr r5, [r12, #244]

	ldr r6, [r12, #248]
	ldr r7, [r12, #252]

	bfi r10, r2, #16, #8
	ldr r1, [sp, #20] // in p

	bfi r11, r3, #16, #8
	ldr r3, [sp, #20+8] // final in_p address at which we break encryption

	eor r8, r4, r8, ror #8
	ldr r2, [sp, #20+4] // out p

	eor r9, r5, r9, ror #8
	ldr r0, [r12, #12] // ctr, incremented at the beginning of the loop

	eor r10, r6, r10, ror #8
	eor r11, r7, r11, ror #8

	//load input, xor keystream and write to output
	ldmia r1!, {r4-r7}

	eor r4, r8
	eor r5, r9

	eor r6, r10
	eor r7, r11

	stmia r2!, {r4-r7}

	cmp r3, r1 // at least exit is an one off case
	beq ctr_exit //if in_p == final_p: exit

	str r1, [sp, #20] // in p
	tst r0, #0xff000000 // set flags early

	str r2, [sp, #20+4] // out p
	bne ctr_encrypt_block //if ctr%256==0: partial_precompute

	nop
	b ctr_partial_precompute

ctr_exit:

	add sp, #20+12
	pop {r4-r11,pc}
