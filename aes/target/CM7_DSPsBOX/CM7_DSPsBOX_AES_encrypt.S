/*!
 * \file CM7_DSPsBOX_AES_encrypt.S
 * \brief
 *
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date Feb 2019
 */

.syntax unified
.thumb
.text

.align 3
	nop.w // 8 byte alignment
// void CM7_DSPsBOX_AES_encrypt2(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM7_DSPsBOX_AES_encrypt2
.type   CM7_DSPsBOX_AES_encrypt2,%function
CM7_DSPsBOX_AES_encrypt2:
#if __ARM_ARCH_7EM__
	add r3, r0, r3, lsl #4 //rk_end-16 = rk + rounds * 16
	push {r3,r4-r11,lr} //stack rk_end-16

	mov r12, r0
	str r2, [sp, #-4]! // push evenly // stack out

	movw r14, #:lower16:AES_sbox
	movt r14, #:upper16:AES_sbox

	//load input
	ldmia r1!, {r4-r7}
	//load key
	ldmia r12!, {r0-r3}

	//initial addroundkey
	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

1:	//shiftrows and subbytes

	//prepare column 0 asap
	//uxtb have to be older opcode
	//uxtb cannot be dual issued so use lsr/and when possible

	lsr.w r8, r3, #24 //row 3 col 0
	uxtb r9, r2, ror #16 //row 2 col 0

	and r11, r0, #0x000000ff //row 0 col 0
	uxtb r10, r1, ror #8 //row 1 col 0

	//now we can load without stalls

	ldrb r8, [r14, r8]
	lsr.w r4, r0, #24 //row 3 col 1

	ldrb r9, [r14, r9]
	uxtb r5, r3, ror #16 //row 2 col 1

	ldrb r10, [r14, r10]
	and r6, r1, #0x000000ff//uxtb.w r6, r1 //row 0 col 1

	ldrb r11, [r14, r11]
	uxtb r7, r2, ror #8 //row 1 col 1

	ldrb r4, [r14, r4]
	orr.w r9, r9, r8, lsl #8 // column 0 upper part

	// now try to free up r0

	ldrb r5, [r14, r5]
	uxtb r8, r0, ror #16 //row 2 col 2

	ldrb r6, [r14, r6]
	orr.w r11, r11, r10, lsl #8 // column 0 bottom part

	ldrb r7, [r14, r7]
	uxtb r10, r0, ror #8 //row 1 col 3

	ldr r0, [r12], #4 // need to put something here
	orr.w r11, r11, r9, lsl #16 // col 0

	//repack column 1 to relax pressure

	ldrb r8, [r14, r8]
	orr.w r5, r5, r4, lsl #8 // column 1 upper part

	ldrb r10, [r14, r10]
	orr.w r7, r6, r7, lsl #8 //column 1 bottom part

	lsr.w r4, r1, #24 //row 3 col 2
	eor r9, r11, r11, ror #8 // start mixing col 0

	and.w r6, r2, 0x000000ff //row 0 col 2 // cant uxtb row1 as older nor younger opcode so do row0
	orr.w r7, r7, r5, lsl #16 //col 1

	//current alloctaion
	// r0 - rk[0]
	// r1 - old c1 -> row 2 col 3
	// r2 - old c2 -> row 3 col 3
	// r3 - old c3 -> row 0 col 3
	// r4 - -> row 3 col 2
	// r5 - -> row 1 col 2
	// r6 - -> row 0 col 2
	// r7 - col 1
	// r8 - row 2 col 2
	// r9 - (col 0 mix columns tmp1)
	// r10 - row 1 col 3
	// r11 - col 0 -> (col0 mix)

	/* do mix columns as
	eor tmp1, r0, r0, ror #8 // r4 = s0^s1 | s1^s2 | s2^s3 | s3^s0
	eor r0, tmp1, r0, ror #16 // r0 = s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3
	uadd8 tmp2, tmp1, tmp1 // quad lsl #1
	eor tmp3, tmp2, #0x1b1b1b1b
	sel tmp4, tmp3, tmp2 // if uadd carried then take reduced byte
	eor r0, tmp4, r0, ror #8 // effective r0 = s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2
	eor r0, r0, rk[n] // and final addroundkey

	alternatively
	eor tmp1, r0, r0, ror #8 // r4 = s0^s1 | s1^s2 | s2^s3 | s3^s0
	eor r0, tmp1, r0, ror #16 // r5 = s0^s1^s2 | s1^s2^s3 | s0^s2^s3 | s0^s1^s3
	eor r0, rk[n], r0, ror #8 // effective r0 = s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2

	//2nd stage - no inline shifts and single cycle dependency
	uadd8 tmp2, tmp1, tmp1 // quad lsl #1
	eor tmp3, tmp2, #0x1b1b1b1b
	sel tmp4, tmp3, tmp2 // if uadd carried then take reduced byte
	eor r0, r0, tmp4
	*/

	ldrb r4, [r14, r4]
	uxtb r5, r3, ror #8 //row 1 col 2

	ldrb r6, [r14, r6]
	uxtb r1, r1, ror #16 //row 2 col 3

	lsr.w r2, r2, #24 //row 3 col 3 //cant ldrb r5 here
	eor r11, r9, r11, ror #16 // col 0 mix

	ldrb r5, [r14, r5]
	orr.w r4, r8, r4, lsl #8 // col 2 upper part

	and.w r3, r3, #0x000000ff //row 0 col 3 // do not load here since we have a lot of inline shift ops to fit somewhere
	eor r0, r0, r11, ror #8 // col 0 mix // r5 not available yet // continue alternate mixing

	ldrb r2, [r14, r2]
	orr.w r5, r6, r5, lsl #8 // col 2 bottom part

	ldrb r1, [r14, r1]
	orr.w r4, r5, r4, lsl #16 // col 2

	ldrb r3, [r14, r3]
	eor r6, r7, r7, ror #8 // col 1 mix

	// current allocation
	// r0 - rk[0] ^ s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2
	// r1 - row 2 col 3 -> rk[1] -> rk[1] ^ s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2
	// r2 - row 3 col 3 -> rk[2]
	// r3 - row 0 col 3 -> rk[3]
	// r4 - col 2
	// r5 - -> col 3 upper -> col 3
	// r6 - (col1 mix tmp1)
	// r7 - col 1
	// r8 -
	// r9 - col0 mix tmp1 // 2nd stage
	// r10 - row 1 col 3 -> col 3 bottom
	// r11 - -> cmp

	ldr r11, [sp, #4]
	orr.w r5, r1, r2, lsl #8 //col 3 upper part

	ldr r1, [r12], #4
	eor r7, r6, r7, ror #16 // col 1 mix

	ldr r2, [r12], #4
	orr.w r10, r3, r10, lsl #8 // col 3 bottom part

	// current allocation
	// r0 - rk[0] ^ s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2
	// r1 - rk[1] ^ s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2
	// r2 - rk[2] -> rk[2] ^ s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2
	// r3 -       -> rk[3] ^ s1^s2^s3 | s0^s2^s3 | s0^s1^s3 | s0^s1^s2
	// r4 - col 2                  ->             -> col 2 tmp4
	// r5 - col 3 upper -> col 3   -> col 3 tmp3  -> col 3 tmp4
	// r6 - col1 mix tmp1          ->             -> col 1 tmp4
	// r7 -                        -> col 2 tmp   ->
	// r8 -                        -> col 3 tmp1  ->
	// r9 - col0 mix tmp1          -> col 3 tmp2  ->
	// r10 - col 3 bottom          -> col1 tmp3   ->
	// r11 - cmp -> col 0 mix tmp3 ->             -> col 0 tmp4

	// now dsp instructions needs to be older opcodes and inline shifts ops younger
	// need one non shifting cycle to allow transition
	// need to end dsp mixing 2 cycles before branch so rework around last ldr

	ldr r3, [r12], #4
	uadd8 r9, r9, r9 // col 0 mix //eor r1, r1, r7, ror #8 // col 1 mix

	cmp.w r12, r11 // cmp should be 3 or 4 cycles ahead for best perf // in case of waitstates maybe earlier
	eor r11, r9, #0x1b1b1b1b // col 0 mix

	eor r1, r1, r7, ror #8 // col 1 mix back
	sel r11, r11, r9 // mixed column 0 // hold the eor for case of emergency

	orr.w r5, r10, r5, lsl #16 // finish col 3
	uadd8 r6, r6, r6 // col 1 mix

	eor.w r7, r4, r4, ror #8 // col 2 mix
	eor r10, r6, #0x1b1b1b1b // col 1 mix

	eor.w r4, r7, r4, ror #16 // col 2 mix
	sel r6, r10, r6 // mixed column 1 // hold the eor for case of emergency

	// col 2 ready before here

	eor r8, r5, r5, ror #8 // col 3 mix
	uadd8 r7, r7, r7  // col 2 mix

	eor r2, r2, r4, ror #8 //col 2 mix back
	eor.w r4, r7, #0x1b1b1b1b // col 2 mix

	eor r5, r8, r5, ror #16 // col 3 mix
	sel r4, r4, r7 // mixed column 2

	//col 3 ready before here

	eor.w r0, r0, r11 // finish col 0
	uadd8 r9, r8, r8 // col 3 mix

	eor r3, r3, r5, ror #8 // col 3 mix back
	eor.w r8, r9, #0x1b1b1b1b // col 3 mix

	//a total of 2 cycles is lost somewhere below here

	eor.w r1, r1, r6 //finish col 1
	sel r5, r8, r9 // mixed column 3

	eor.w r2, r2, r4 // finish col 2
	eor.w r3, r3, r5 // finish col 3

	nop.w
	bne.w 1b // above short range

	//final round // recycle code
	//and now uxtb have to be younger op // ubfx does the same

	uxtb r9, r2, ror #16 //row 2 col 0
	lsr.w r8, r3, #24 //row 3 col 0

	uxtb r10, r1, ror #8 //row 1 col 0
	and r11, r0, #0x000000ff //row 0 col 0

	lsr.w r4, r0, #24 //row 3 col 1
	ldrb r8, [r14, r8]

	uxtb r5, r3, ror #16 //row 2 col 1
	ldrb r9, [r14, r9]

	and r6, r1, #0x000000ff//uxtb.w r6, r1 //row 0 col 1
	ldrb r10, [r14, r10]

	uxtb r7, r2, ror #8 //row 1 col 1
	ldrb r11, [r14, r11]

	orr.w r9, r9, r8, lsl #8 // column 0 upper part
	ldrb r4, [r14, r4]

	uxtb r8, r0, ror #16 //row 2 col 2
	ldrb r5, [r14, r5]

	orr.w r11, r11, r10, lsl #8 // column 0 bottom part
	ldrb r6, [r14, r6]

	uxtb r10, r0, ror #8 //row 1 col 3
	ldrb r7, [r14, r7]

	orr.w r11, r11, r9, lsl #16 // col 0
	ldr r0, [r12, #0] // column 0 is ready to eor and store

	orr.w r5, r5, r4, lsl #8 // column 1 upper part
	ldrb r8, [r14, r8]

	orr.w r7, r6, r7, lsl #8 //column 1 bottom part
	ldrb r10, [r14, r10]

	orr.w r7, r7, r5, lsl #16 //col 1
	lsr.w r4, r1, #24 //row 3 col 2

	uxtb r5, r3, ror #8 //row 1 col 2
	and.w r6, r2, 0x000000ff //row 0 col 2

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
	ldrb r4, [r14, r4]

	lsr.w r2, r2, #24 //row 3 col 3
	ldrb r6, [r14, r6] // swp

	and.w r3, r3, #0x000000ff //row 0 col 3
	ldrb r5, [r14, r5] // swp

	orr.w r4, r8, r4, lsl #8 // col 2 upper part
	ldrb r9, [r14, r9]

	eor r0, r0, r11 // finish col 0
	ldrb r2, [r14, r2]

	orr.w r5, r6, r5, lsl #8 // col 2 bottom part
	ldrb r3, [r14, r3]

	orr.w r4, r5, r4, lsl #16 // col 2
	ldr r1, [r12, #4] // rk[1]

	//current allocation
	// r0 - finished col 0
	// r1 - rk[1]
	// r2 - row 3 col 3  -> rk[2]
	// r3 - row 0 col 3
	// r4 - col 2
	// r5 -              -> output p
	// r6 -              -> col 3 upper
	// r7 - col 1
	// r8 -
	// r9 - row 2 col 3  ->
	// r10 - row 1 col 3 -> col 3 bottom
	// r11 -

	orr.w r6, r9, r2, lsl #8 //col 3 upper part
	ldr r5, [sp], #8 // load output pointer and clear stack

	orr.w r10, r3, r10, lsl #8 // col 3 bottom part
	ldr r2, [r12, #8] // rk[2]

	eor.w r1, r1, r7
	ldr r3, [r12, #12]

	eor.w r2, r2, r4
	str.w r0, [r5, #0]

	orr.w r6, r10, r6, lsl #16 // finish col 3
	str.w r1, [r5, #4]

	str.w r2, [r5, #8]
	ldr r4, [sp], #4 // pop early to pop even number of registers

	eor.w r3, r3, r6
	str.w r3, [r5, #12]

	pop {r5-r11,pc}
#else
	//crash in case the function was called on non dsp cortex m3
	b .
#endif
