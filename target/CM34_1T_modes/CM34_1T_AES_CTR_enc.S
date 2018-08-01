// counter mode, SP 800-38A compliant (32bit, big endian ctr)
// UNOPTIMIZED // working

.syntax unified
.thumb
.text

.align 3
// void CM34_1T_CTR_enc(void* ctx, uint8_t* data_in, uint8_t* data_out, uint32_t rounds, uint32_t blocks_cnt) {
.global CM34_1T_AES_CTR_enc
.type   CM34_1T_AES_CTR_enc,%function
CM34_1T_AES_CTR_enc:
	push {r3}
	add r3, r0, r3, lsl #4 //rk_end-16 = rk + rounds * 16
	adds r3, #16
	push {r1-r11,lr}


	//sub sp, #20
	mov.w r14, r0

	movw r12, #:lower16:AES_Te0
	movt r12, #:upper16:AES_Te0


ctr_partial_precompute:

	//load from ctx nonce in r0-r3, key in r4-r7
    ldmia r14!, {r0-r7}

    //initial addroundkey
    eors r4, r0
    eors r5, r1
    eors r6, r2
    eors r7, r3

	//and r7, r7, #0xffffff00
	//and r7, r7, #0x00ffffff

	//round 1
	ldmia r14!, {r8-r11}

    uxtb r0, r4 // LE/LEFT
    uxtb r1, r5
    uxtb r2, r6
    uxtb r3, r7
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #16
    eor r9, r9, r1, ror #16
    eor r10, r10, r2, ror #16
    eor r11, r11, r3, ror #16

    uxtb r0, r5, ror #8
    uxtb r1, r6, ror #8
    uxtb r2, r7, ror #8
    uxtb r3, r4, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #8
    eor r9, r9, r1, ror #8
    eor r10, r10, r2, ror #8
    eor r11, r11, r3, ror #8

    uxtb r0, r6, ror #16
    uxtb r1, r7, ror #16
    uxtb r2, r4, ror #16
    uxtb r3, r5, ror #16
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r0
    eor r9, r1
    eor r10, r2
    eor r11, r3

    //uxtb r0, r7, ror #24 // BE/RIGHT
    uxtb r1, r4, ror #24
    uxtb r2, r5, ror #24
    uxtb r4, r6, ror #24
    //ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r4, [r12, r4, lsl #2]

    //ldr r3, [r12, #0] //keep this value here throughout round 2 to save loads

    //eor r8, r8, r0, ror #24
    eor r9, r9, r1, ror #24
    eor r10, r10, r2, ror #24
    eor r11, r11, r4, ror #24

    //eor r1, r8, r3, ror #16
    //eor r1, r8, r3, ror #24
    //push.w {r1} // precomputed x0
	push {r8}

	//round 2
	ldmia r14!, {r4-r7}

	//r8
	uxtb r0, r9
    uxtb r1, r10
    uxtb r2, r11
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    //eor r4, r4, r3, ror #16
    eor r5, r5, r0, ror #16
    eor r6, r6, r1, ror #16
    eor r7, r7, r2, ror #16

    uxtb r0, r9, ror #8
    uxtb r1, r10, ror #8
    uxtb r2, r11, ror #8
    //r8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    eor r4, r4, r0, ror #8
    eor r5, r5, r1, ror #8
    eor r6, r6, r2, ror #8
    //eor r7, r7, r3, ror #8

    uxtb r0, r10, ror #16
    uxtb r1, r11, ror #16
    //r8
    uxtb r2, r9, ror #16
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    eor r4, r0
    eor r5, r1
    //eor r6, r3
    eor r7, r2

    uxtb r0, r11, ror #24
    //r8
    uxtb r1, r9, ror #24
    uxtb r2, r10, ror #24
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    eor r4, r4, r0, ror #24
    //eor r5, r5, r3, ror #24
    eor r6, r6, r1, ror #24
    eor r7, r7, r2, ror #24

    //eor r4, r4, r3, ror #16
    //eor r5, r5, r3, ror #24
    //eor r6, r3
    //eor r7, r7, r3, ror #8

    push.w {r4-r7}
    //load precomputed_x0
    ldr r10, [sp, #16]
    //the first time, we can skip some loads
	b.w ctr_encrypt_first

ctr_encrypt_block: //expect {precomputed_y0..y3, precomputed_x0} on top of stack, p+4*4*4 in r14

    //load precomputed
    ldm sp, {r4-r7,r10}

ctr_encrypt_first:

    //load ctr +3
    ldr r8, [r14, #-52] // -64
    //load key[0] +3
    ldr r9, [r14, #-36] // -48

    //round 1  // r0 ror24
    eor r8, r9
    //and r8, #0xff
    uxtb r8, r8, ror #24

    ldr r8, [r12, r8, lsl #2]
    //eor r10, r10, r8, ror #16
    eor r10, r10, r8, ror #24

    //round 2
    uxtb r0, r10
    uxtb r1, r10, ror #24
    uxtb r2, r10, ror #16
    uxtb r3, r10, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r4, r0, ror #16
    eor r5, r5, r1, ror #24
    eor r6, r6, r2
	eor r7, r7, r3, ror #8



1:	ldmia r14!, {r8-r11}

    uxtb r0, r4
    uxtb r1, r5
    uxtb r2, r6
    uxtb r3, r7
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #16
    eor r9, r9, r1, ror #16
    eor r10, r10, r2, ror #16
    eor r11, r11, r3, ror #16

    uxtb r0, r5, ror #8
    uxtb r1, r6, ror #8
    uxtb r2, r7, ror #8
    uxtb r3, r4, ror #8
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r8, r0, ror #8
    eor r9, r9, r1, ror #8
    eor r10, r10, r2, ror #8
    eor r11, r11, r3, ror #8

    uxtb r0, r6, ror #16
    uxtb r1, r7, ror #16
    uxtb r2, r4, ror #16
    uxtb r3, r5, ror #16
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r8, r0
    eor r9, r1
    eor r10, r2
    eor r11, r3

    uxtb r0, r7, ror #24
    uxtb r1, r4, ror #24
    uxtb r2, r5, ror #24
    uxtb r3, r6, ror #24
    ldr r0, [r12, r0, lsl #2]
    ldr r1, [r12, r1, lsl #2]
    ldr r2, [r12, r2, lsl #2]
    ldr r3, [r12, r3, lsl #2]
    eor r4, r8, r0, ror #24
    eor r5, r9, r1, ror #24
    eor r6, r10, r2, ror #24
	eor r7, r11, r3, ror #24

	ldr r0, [sp, #28]
	cmp r0, r14

	bne 1b

	//final round
	uxtb r8, r7, ror #24
	uxtb r9, r4, ror #24
	uxtb r10, r5, ror #24
	uxtb r11, r6, ror #24
	ldr r8, [r12, r8, lsl #2]
	ldr r9, [r12, r9, lsl #2]
	ldr r10, [r12, r10, lsl #2]
	ldr r11, [r12, r11, lsl #2]

	uxtb r0, r6, ror #16
	uxtb r1, r7, ror #16
	uxtb r2, r4, ror #16
	uxtb r3, r5, ror #16
	ldr r0, [r12, r0, lsl #2]
	ldr r1, [r12, r1, lsl #2]
	ldr r2, [r12, r2, lsl #2]
	ldr r3, [r12, r3, lsl #2]

	bfi r8, r0, #24, #8
	bfi r9, r1, #24, #8
	bfi r10, r2, #24, #8
	bfi r11, r3, #24, #8

	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r12, r0, lsl #2]
	ldr r1, [r12, r1, lsl #2]
	ldr r2, [r12, r2, lsl #2]
	ldr r3, [r12, r3, lsl #2]
	bfi r8, r0, #8, #8
	bfi r9, r1, #8, #8
	bfi r10, r2, #8, #8
	bfi r11, r3, #8, #8

	uxtb r0, r5, ror #8
	uxtb r1, r6, ror #8
	uxtb r2, r7, ror #8
	uxtb r3, r4, ror #8
	ldr r0, [r12, r0, lsl #2]
	ldr r1, [r12, r1, lsl #2]
	ldr r2, [r12, r2, lsl #2]
	ldr r3, [r12, r3, lsl #2]

	bfi r8, r0, #16, #8
	bfi r9, r1, #16, #8
	bfi r10, r2, #16, #8
	bfi r11, r3, #16, #8

    ldmia r14!, {r0-r3}

	eor r4, r0, r8, ror #8
	eor r5, r1, r9, ror #8
	eor r6, r2, r10, ror #8
	eor r7, r3, r11, ror #8

    //load in, out, len counter
    //add r8, sp, #20 //step over precomputed_*
    //ldmia r8, {r1-r3}

    ldr r1, [sp, #20+0] // in p
    ldr r2, [sp, #20+4] // out p
    ldr r3, [sp, #20+48+4] // blocks len // argument passed through stack

    //load input, xor keystream and write to output
    ldmia r1!, {r8-r11}
    str r1, [sp, #20]
    eor r4, r8
    eor r5, r9
    eor r6, r10
    eor r7, r11
    stmia r2!, {r4-r7}
    str r2, [sp, #24]

	ldr r0, [sp, #20+48]
	lsl r0, #4// *16
	subs r0, #32

    //load, inc, store ctrnonce
    sub r14, r0 //reset to p+4*4*4, as required by encrypt_block
    ldr r4, [r14, #-52]
    rev r4, r4
    add r4, #1
    //ands.w r4, r4, #0xff
    //tst r4, #0xff
    rev r4, r4
    str r4, [r14, #-52]

    //dec and store len counter
    subs r3, #1
    beq ctr_exit //if len==0: exit
	str.w r3, [sp, #20+48+4] // blocks len // argument passed through stack

	tst r4, #0xff000000

    //if ctrnonce%256==0: partial_precompute
    bne ctr_encrypt_block

    add.w sp, #20 //remove precomputed_*
    sub r14, #64 //reset to p, as required by partial_precompute
    b ctr_partial_precompute

ctr_exit:

	add sp, #20+12
	pop {r4-r11,lr}
	pop {r0}
	bx lr
