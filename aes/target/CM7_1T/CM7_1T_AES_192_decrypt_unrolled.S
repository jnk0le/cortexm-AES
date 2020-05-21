// uses backward expanded round key

.include "aes/target/CM7_1T/CM7_1T_AES_common.inc"

.syntax unified
.thumb
.text
//.section .itcm.text, "x"

.align 3
// void CM7_1T_AES_192_decrypt_unrolled(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM7_1T_AES_192_decrypt_unrolled
.type   CM7_1T_AES_192_decrypt_unrolled,%function
CM7_1T_AES_192_decrypt_unrolled:
	pld [r1, #0] // dead cycle anyway, preload in case data is still in external mem, cacheline is 32 bytes
	add r12, r0, #192 // 10 rounds * 16

	push {r2, r4-r11, lr} //stack out

	movw r14, #:lower16:AES_Td2
	movt r14, #:upper16:AES_Td2

	//load input
	//ldmia.w r1!, {r4-r7}  //it has to be 8 byte aligned before first round

	ldr r4, [r1, #0]
	ldr r5, [r1, #4]

	ldr r6, [r1, #8]
	ldr r7, [r1, #12]

	//load initial round key
	ldm r12, {r0-r3}

	//initial addroundkey
	eor.w r0, r4
	eor.w r1, r5

	eor.w r2, r6
	eor.w r3, r7

	CM7_1T_unrolled_dec_round // 1
	CM7_1T_unrolled_dec_round // 2
	CM7_1T_unrolled_dec_round // 3
	CM7_1T_unrolled_dec_round // 4
	CM7_1T_unrolled_dec_round // 5
	CM7_1T_unrolled_dec_round // 6
	CM7_1T_unrolled_dec_round // 7
	CM7_1T_unrolled_dec_round // 8
	CM7_1T_unrolled_dec_round // 9
	CM7_1T_unrolled_dec_round // 10
	CM7_1T_unrolled_dec_round // 11

	//final round
	movw r14, #:lower16:AES_inv_sbox
	movt r14, #:upper16:AES_inv_sbox

	uxtb r4, r2, ror #16 // row 2 col 0
	lsr.w r5, r1, #24 // row 3 col 0

	uxtb r6, r3, ror #8 // row 1 col 0
	and.w r7, r0, #0xff // row 0 col 0

	lsr.w r8, r2, #24 //row 3 col 1
	ldrb r5, [r14, r5]

	uxtb r9, r3, ror #16 // row 2 col 1
	ldrb r4, [r14, r4]

	uxtb r10, r0, ror #8 // row 1 col 1
	ldrb r6, [r14, r6]

	uxtb r11, r1 // row 0 col 1
	ldrb r7, [r14, r7]

	orr.w r4, r4, r5, lsl #8  //column 0 upper part
	ldrb r8, [r14, r8]

	// clear r0 first

	uxtb r5, r0, ror #24 // row 3 col 3
	ldrb r9, [r14, r9]

	orr.w r6, r7, r6, lsl #8 // column 0 bottom part
	ldrb r10, [r14, r10]

	uxtab r7, r14, r0, ror #16 // row 2 col 2
	ldrb r11, [r14, r11]

	//current allocation
	// r0 -
	// r1 - old col 1
	// r2 - old col 2
	// r3 - old col 3
	// r4 - col 0 upper
	// r5 - row 3 col 3
	// r6 - col 0 bottom
	// r7 - row 2 col 2
	// r8 - row 3 col 1
	// r9 - row 2 col 1
	// r10 - row 1 col 1
	// r11 - row 0 col 1

	orr.w r4, r6, r4, lsl #16 // col 0
	ldrb r5, [r14, r5]

	//clear r1
	uxtb r6, r1, ror #8 // row 1 col 2 // cannot uxtab
	orr.w r8, r9, r8, lsl #8 // col 1 upper part

	uxtb r9, r1, ror #16 // row 2 col 3
	orr.w r10, r11, r10, lsl #8 // col 1 bottom part

	//current allocation
	// r0 -
	// r1 -
	// r2 - old col 2
	// r3 - old col 3
	// r4 - col 0
	// r5 - row 3 col 3
	// r6 - row 1 col 2
	// r7 - row 2 col 2
	// r8 - col 1 upper
	// r9 - row 2 col 3
	// r10 - col 1 bottom
	// r11 -

	//clear r2
	uxtb r11, r2, ror #8 // row 1 col 3
	ldrb.w r7, [r7]

	orr.w r8, r10, r8, lsl #16 // col 1
	ldrb r9, [r14, r9]

	uxtb r10, r2 // row 0 col 2
	ldrb r6, [r14, r6]

	//current allocation
	// r0 -
	// r1 -
	// r2 -
	// r3 - old col 3
	// r4 - col 0
	// r5 - row 3 col 3
	// r6 - row 1 col 2
	// r7 - row 2 col 2
	// r8 - col 1
	// r9 - row 2 col 3
	// r10 - row 0 col 2
	// r11 - row 1 col 3

	// clear r3

	uxtb.w r2, r3 //row 0 col 3
	ldrb r11, [r14, r11]

	lsr.w r1, r3, #24 // row 3 col 2
	ldrb r10, [r14, r10]

	orr.w r5, r9, r5, lsl #8 // col 3 upper part
	ldrb r9, [r14, r2]

	//current allocation
	// r0 -
	// r1 - row 3 col 2
	// r2 -
	// r3 -
	// r4 - col 0
	// r5 - col 3 upper
	// r6 - row 1 col 2
	// r7 - row 2 col 2
	// r8 - col 1
	// r9 - row 0 col 3
	// r10 - row 0 col 2
	// r11 - row 1 col 3

	orr.w r10, r10, r6, lsl #8 // col 2 bottom part
	ldrb r6, [r14, r1]

	//current allocation
	// r0 -
	// r1 -
	// r2 -
	// r3 -
	// r4 - col 0
	// r5 - col 3 upper
	// r6 - row 3 col 2
	// r7 - row 2 col 2
	// r8 - col 1
	// r9 - row 0 col 3
	// r10 - col 2 bottom
	// r11 - row 1 col 3

	eor.w r11, r9, r11, lsl #8 // col 3 bottom
	ldr r0, [r12, #-16]!

	eor.w r5, r11, r5, lsl #16 // col 3
	ldr r1, [r12, #4]

	orr.w r7, r7, r6, lsl #8 // col 2 upper
	ldr r2, [r12, #8]

	orr.w r0, r4
	ldr r3, [r12, #12]

	//current allocation
	// r0 - finished col 0
	// r1 - rk[1]
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 -
	// r5 - col 3
	// r6 -
	// r7 - col 2 upper
	// r8 - col 1
	// r9 -
	// r10 - col 2 bottom
	// r11 -

	eor.w r1, r8
	ldr r6, [sp], #4 //load output pointer and clear stack

	orr.w r7, r10, r7, lsl #16 // col2
	ldr r4, [sp], #4 // pop early to pop even number of registers later

	eor.w r2, r7
	eor.w r3, r5

	stmia r6!, {r0-r3}

	pop {r5-r11, pc}
