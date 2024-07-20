/*!
 * \file CM3_1T_AES_CTR32_enc.S
 * \brief
 *
 * counter mode, SP 800-38A compliant (32bit, big endian ctr), can start from any counter value
 * counter is written back and can be used to continue encryption later
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * Peter Schwabe & Ko Stoffelen @2016
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only
#if __ARM_EABI__ && __thumb2__

.syntax unified
.thumb
.text

.balign 4
// void CM3_1T_AES_CTR32_enc(void* ctx, uint8_t* data_in, uint8_t* data_out, uint32_t rounds, uint32_t blocks_cnt) {
.global CM3_1T_AES_CTR32_enc
.type   CM3_1T_AES_CTR32_enc,%function
CM3_1T_AES_CTR32_enc:
	mov r12, r0
	adds r0, #64 // 3rd round as common reload point

	push {r0-r2,r4-r11,lr} // push ctx+64, data_in, data_out

	add r11, r12, r3, lsl #4 //rk_end-16 = rk + rounds * 16
	add.w r11, #16 // + nonce

	movw r14, #:lower16:AES_Te2
	movt r14, #:upper16:AES_Te2

	ldr r0, [sp, #48]
	add r0, r1, r0, lsl #4 // in_p + cnt*16
	str r0, [sp, #48]

	sub.w sp, #20 // align loop entry

	// sp
	// +0  - precomputed_y0
	// +4  - precomputed_y1
	// +8  - precomputed_y2
	// +12 - precomputed_y3
	// +16 - precomputed_x0

	// +20 - ctx+64
	// +24 - data_in
	// +28 - data_out

	// stacked registers

	// +68 - (blocks_cnt) -> data_end

	// global allocation
	// r11 - inner loop final ptr
	// r12 - current rk ptr
	// r14 - Te2

ctr_partial_precompute:

	//load from ctx, nonce in r0-r3, key in r4-r7
	ldmia r12!, {r0-r7}

	//initial addroundkey
	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	// round 1
	// s33 is lowest byte of counter, can't be precomputed

	// r0 - s00 | s10 | s20 | s30
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 |  x

	// rotation after Te2
	// xor   16 |  8  |  0  |  24

	// c0 - s00T ^ s11T ^ s22T
	// c1 - s01T ^ s12T ^ s23T ^ s30T
	// c2 - s02T ^ s13T ^ s20T ^ s31T
	// c3 - s03T ^ s10T ^ s21T ^ s32T

	uxtb.w r4, r0 // align loads
	uxtb.w r9, r1, ror #8
	uxtb.w r10, r2, ror #16
	uxtb.w r8, r3, ror #16
	uxtb r5, r1
	lsrs r7, r0, #24

	ldr.w r4, [r14, r4, lsl #2]
	ldr.w r9, [r14, r9, lsl #2]
	ldr.w r10, [r14, r10, lsl #2]
	ldr.w r8, [r14, r8, lsl #2]
	ldr.w r5, [r14, r5, lsl #2]
	ldr.w r7, [r14, r7, lsl #2]

	//current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00T // c0 ror16
	// r5 - s01T // c1 ror16
	// r6 -
	// r7 - s30T // c1 ror24
	// r8 - s23T // c1 ror0
	// r9 - s11T // c0 ror8
	// r10 - s22T // c0 ror0

	eor.w r4, r10, r4, ror #16
	eor.w r4, r4, r9, ror #8
	eor.w r5, r8, r5, ror #16
	eor.w r5, r5, r7, ror #24

	uxtb r6, r2
	uxtb r7, r3
	uxtb.w r8, r0, ror #16
	uxtb.w r9, r2, ror #8
	uxtb.w r10, r1, ror #16
	uxtb.w r3, r3, ror #8
	uxtb.w r0, r0, ror #8
	lsrs r1, r1, #24
	lsrs r2, r2, #24

	ldr.w r6, [r14, r6, lsl #2]
	ldr.w r7, [r14, r7, lsl #2]
	ldr.w r8, [r14, r8, lsl #2]
	ldr.w r9, [r14, r9, lsl #2]
	ldr.w r10, [r14, r10, lsl #2]
	ldr.w r3, [r14, r3, lsl #2]
	ldr.w r0, [r14, r0, lsl #2]
	ldr.w r1, [r14, r1, lsl #2]
	ldr.w r2, [r14, r2, lsl #2]

	//current allocation
	// r0 - s10T // c3 ror8
	// r1 - s31T // c2 ror24
	// r2 - s32T // c2 ror24
	// r3 - s13T // c2 ror8
	// r4 - s00T ^ s11T ^ s22T // c0
	// r5 - s01T ^ s23T ^ s30T // c1
	// r6 - s02T // c2 ror16
	// r7 - s03T // c3 ror16
	// r8 - s20T // c2 ror0
	// r9 - s12T // c1 ror8
	// r10 - s21T // c3 ror0

	eor.w r5, r5, r9, ror #8
	eor.w r6, r8, r6, ror #16
	eor.w r7, r10, r7, ror #16
	eor.w r6, r6, r3, ror #8
	eor.w r7, r7, r0, ror #8
	eor.w r6, r6, r1, ror #24
	eor.w r7, r7, r2, ror #24

	ldmia.w r12!, {r0-r3} // load rk

	//current allocation
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 - s00T ^ s11T ^ s22T // c0
	// r5 - s01T ^ s12T ^ s23T ^ s30T // c1
	// r6 - s02T ^ s13T ^ s20T ^ s31T // c2
	// r7 - s03T ^ s10T ^ s21T ^ s32T // c3
	// r8 -
	// r9 -
	// r10 -

	// change order for more efficient 2nd round precomp
	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	// round 2
	// don't touch r4 until stored

	// r4 -  x  |  x  |  x  |  x
	// r5 - s01 | s11 | s21 | s31
	// r6 - s02 | s12 | s22 | s32
	// r7 - s03 | s13 | s23 | s33

	// rotation after Te2
	// xor   16 |  8  |  0  |  24

	// c0 -      ^ s11T ^ s22T ^ s33T
	// c1 - s01T ^ s12T ^ s23T ^
	// c2 - s02T ^ s13T ^      ^ s31T
	// c3 - s03T ^      ^ s21T ^ s32T

	uxtb r1, r5
	uxtb r2, r6
	uxtb.w r8, r7, ror #16
	uxtb.w r9, r6, ror #8
	uxtb.w r10, r7, ror #8
	uxtb.w r0, r5, ror #8
	uxtb.w r3, r6, ror #16

	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r8, [r14, r8, lsl #2]
	ldr r9, [r14, r9, lsl #2]
	ldr r10, [r14, r10, lsl #2]
	ldr r0, [r14, r0, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	str.w r4, [sp, #16] // precomputed x0 // .w required

	//current allocation
	// r0 - s11T // c0 ror8
	// r1 - s01T // c1 ror16
	// r2 - s02T // c2 ror16
	// r3 - s22T // c0 ror0
	// r4 -
	// r5 -  -  |  -  | s21 | s31
	// r6 -  -  |  -  |  -  | s32
	// r7 - s03 |  -  |  -  | s33
	// r8 - s23T // c1 ror0
	// r9 - s12T // c1 ror8
	// r10 - s13T // c2 ror8

	eor.w r1, r8, r1, ror #16
	eor.w r4, r1, r9, ror #8
	eor.w r10, r10, r2, ror #8 // effective ror #16
	eor.w r9, r3, r0, ror #8

	ldmia r12!, {r0-r3} // load rk early

	//current allocation
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 - s01T ^ s12T ^ s23T ^ // c1
	// r5 -  -  |  -  | s21 | s31
	// r6 -  -  |  -  |  -  | s32
	// r7 - s03 |  -  |  -  | s33
	// r8 -
	// r9 -  ^ s11T ^ s22T ^ // c0
	// r10 - s02T ^ s13T // c2 ror8

	eors.w r1, r4 // align

	uxtb.w r8, r5, ror #16
	uxtb r4, r7
	lsrs r5, r5, #24
	lsrs r6, r6, #24
	lsrs r7, r7, #24

	ldr r8, [r14, r8, lsl #2]
	ldr r4, [r14, r4, lsl #2]
	ldr r5, [r14, r5, lsl #2]
	ldr r6, [r14, r6, lsl #2]
	ldr r7, [r14, r7, lsl #2]
	str r1, [sp, #4] // precomputed y1

	//current allocation
	// r0 - rk[0]
	// r1 - col 1 (stored)
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 - s03T // c3 ror #16
	// r5 - s31T // c2 ror24
	// r6 - s32T // c3 ror24
	// r7 - s33T // c0 ror24
	// r8 - s21T // c3 ror0
	// r9 - ^ s11T ^ s22T ^ // c0
	// r10 - s02T ^ s13T // c2 ror8

	eor.w r7, r9, r7, ror #24
	eors r0, r7

	eor.w r4, r8, r4, ror #16
	eor.w r4, r4, r6, ror #24
	eors r3, r4
	str r0, [sp, #0] // precomputed y0

	eor.w r5, r10, r5, ror #16 // effective ror #24
	eor.w r2, r2, r5, ror #8 // col2 doesn't heave row2 to null out rotation

	//current allocation
	// r0 - col 0 (stored)
	// r1 - col 1 (stored)
	// r2 - col 2
	// r3 - col 3
	// r4 -
	// r5 -
	// r6 -
	// r7 -
	// r8 -
	// r9 -
	// r10 -

	ldr r5, [r12, #-52] // preload ctr[3]
	str r2, [sp, #8]
	str r3, [sp, #12]

	// the first time, we can skip some loads
	b ctr_encrypt_first

.balign 4
ctr_encrypt_block: // expect {precomputed_y0..y3, precomputed_x0} on top of stack, ctx+64 in r12
	ldr r0, [sp, #0]
	ldr r1, [sp, #4]
	ldr r2, [sp, #8]
	ldr r3, [sp, #12]

ctr_encrypt_first:
	// expect CTR in r5

	// load MSB of key[3]
	ldrb r6, [r12, #-36+3]

	// load precomputed_x0
	ldr r7, [sp, #16]

	// rev and inc ctr here
	rev r4, r5
	adds r4, #1

	//current allocation
	// r0 - precomputed y0
	// r1 - precomputed y1
	// r2 - precomputed y2
	// r3 - precomputed y3
	// r4 - reversed CTR + 1
	// r5 - CTR
	// r6 - k[3] MSB
	// r7 - precomputed x0
	// r8 -
	// r9 -
	// r10 -

	//round 1
	eor.w r5, r6, r5, lsr #24 // truncate ctr, key is already byte
	rev r4, r4
	ldr r5, [r14, r5, lsl #2]
	str r4, [r12, #-52] // store incremented ctr
	eor r7, r7, r5, ror #24

	//round 2
	uxtb.w r4, r7, ror #8 //c3
	uxtb.w r5, r7, ror #16 // c2
	uxtb r6, r7 // c0
	lsrs r7, r7, #24 //c1
	ldr r4, [r14, r4, lsl #2]
	ldr r5, [r14, r5, lsl #2]
	ldr r6, [r14, r6, lsl #2]
	ldr r7, [r14, r7, lsl #2]
	eor.w r0, r0, r6, ror #16
	eor.w r1, r1, r7, ror #24
	eor.w r2, r2, r5 // align loop entry
	eor.w r3, r3, r4, ror #8

	// r0 - s00 | s10 | s20 | s30
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33

	// rotation after Te2
	// xor   16 |  8  |  0  |  24

	// r4 - s00T ^ s11T ^ s22T ^ s33T
	// r5 - s01T ^ s12T ^ s23T ^ s30T
	// r6 - s02T ^ s13T ^ s20T ^ s31T
	// r7 - s03T ^ s10T ^ s21T ^ s32T

1:	uxtb r4, r0
	lsrs r6, r3, #24
	uxtb.w r9, r1, ror #8
	uxtb.w r10, r2, ror #16
	uxtb.w r8, r3, ror #16
	uxtb r5, r1
	lsrs r7, r0, #24

	ldr.w r4, [r14, r4, lsl #2]
	ldr.w r6, [r14, r6, lsl #2]
	ldr.w r9, [r14, r9, lsl #2]
	ldr.w r10, [r14, r10, lsl #2]
	ldr.w r8, [r14, r8, lsl #2]
	ldr.w r5, [r14, r5, lsl #2]
	ldr.w r7, [r14, r7, lsl #2]

	//current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00T // c0 ror16
	// r5 - s01T // c1 ror16
	// r6 - s33T // c0 ror24
	// r7 - s30T // c1 ror24
	// r8 - s23T // c1 ror0
	// r9 - s11T // c0 ror8
	// r10 - s22T // c0 ror0

	eor.w r4, r10, r4, ror #16
	eor.w r4, r4, r9, ror #8
	eor.w r4, r4, r6, ror #24
	eor.w r5, r8, r5, ror #16
	eor.w r5, r5, r7, ror #24

	uxtb r6, r2
	uxtb r7, r3
	uxtb.w r8, r0, ror #16
	uxtb.w r9, r2, ror #8
	uxtb.w r10, r1, ror #16
	uxtb.w r3, r3, ror #8
	uxtb.w r0, r0, ror #8
	lsrs r1, r1, #24
	lsrs r2, r2, #24

	ldr.w r6, [r14, r6, lsl #2]
	ldr.w r7, [r14, r7, lsl #2]
	ldr.w r8, [r14, r8, lsl #2]
	ldr.w r9, [r14, r9, lsl #2]
	ldr.w r10, [r14, r10, lsl #2]
	ldr.w r3, [r14, r3, lsl #2]
	ldr.w r0, [r14, r0, lsl #2]
	ldr.w r1, [r14, r1, lsl #2]
	ldr.w r2, [r14, r2, lsl #2]

	//current allocation
	// r0 - s10T // c3 ror8
	// r1 - s31T // c2 ror24
	// r2 - s32T // c2 ror24
	// r3 - s13T // c2 ror8
	// r4 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r5 - s01T ^ s23T ^ s30T // c1
	// r6 - s02T // c2 ror16
	// r7 - s03T // c3 ror16
	// r8 - s20T // c2 ror0
	// r9 - s12T // c1 ror8
	// r10 - s21T // c3 ror0

	eor.w r5, r5, r9, ror #8
	eor.w r6, r8, r6, ror #16
	eor.w r7, r10, r7, ror #16
	eor.w r6, r6, r3, ror #8
	eor.w r7, r7, r0, ror #8
	eor.w r6, r6, r1, ror #24
	eor.w r7, r7, r2, ror #24

	ldmia.w r12!, {r0-r3} // load rk

	//current allocation
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 - s00T ^ s11T ^ s22T ^ s33T // c0
	// r5 - s01T ^ s12T ^ s23T ^ s30T // c1
	// r6 - s02T ^ s13T ^ s20T ^ s31T // c2
	// r7 - s03T ^ s10T ^ s21T ^ s32T // c3
	// r8 -
	// r9 -
	// r10 -

	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	cmp r11, r12
	bne 1b

	//final round
	// r0 - s00 | s10 | s20 | s30
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33

	//final
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02`| s13`| s20`| s31`
	// r7 - s03`| s10`| s21`| s32`

	uxtb r4, r0
	lsrs r6, r3, #24
	uxtb.w r9, r1, ror #8
	uxtb.w r10, r2, ror #16
	uxtb.w r8, r3, ror #16
	uxtb r5, r1
	lsrs r7, r0, #24

	ldrb.w r4, [r14, r4, lsl #2]
	ldrb.w r6, [r14, r6, lsl #2]
	ldrb.w r9, [r14, r9, lsl #2]
	ldrb.w r10, [r14, r10, lsl #2]
	ldrb.w r8, [r14, r8, lsl #2]
	ldrb.w r5, [r14, r5, lsl #2]
	ldrb.w r7, [r14, r7, lsl #2]

	//current allocation
	// r0 -  -  | s10 | s20 |  -
	// r1 -  -  |  -  | s21 | s31
	// r2 - s02 | s12 |  -  | s32
	// r3 - s03 | s13 |  -  |  -
	// r4 - s00` // c0r0
	// r5 - s01` // c1r0
	// r6 - s33` // c0r3
	// r7 - s30` // c1r3
	// r8 - s23` // c1r2
	// r9 - s11` // c0r1
	// r10 - s22` // c0r2

	orr.w r4, r4, r6, lsl #24
	orr.w r4, r4, r9, lsl #8
	orr.w r4, r4, r10, lsl #16
	orr.w r5, r5, r8, lsl #16
	orr.w r5, r5, r7, lsl #24

	uxtb r6, r2
	uxtb r7, r3
	uxtb.w r8, r0, ror #16
	uxtb.w r9, r2, ror #8
	uxtb.w r10, r1, ror #16
	uxtb.w r3, r3, ror #8
	uxtb.w r0, r0, ror #8
	lsrs r1, r1, #24
	lsrs r2, r2, #24

	ldrb.w r6, [r14, r6, lsl #2]
	ldrb.w r7, [r14, r7, lsl #2]
	ldrb.w r8, [r14, r8, lsl #2]
	ldrb.w r9, [r14, r9, lsl #2]
	ldrb.w r10, [r14, r10, lsl #2]
	ldrb.w r3, [r14, r3, lsl #2]
	ldrb.w r0, [r14, r0, lsl #2]
	ldrb.w r1, [r14, r1, lsl #2]
	ldrb.w r2, [r14, r2, lsl #2]

	//current allocation
	// r0 - s10` // c3r1
	// r1 - s31` // c2r3
	// r2 - s32` // c3r3
	// r3 - s13` // c2r1
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`|     | s23`| s30`
	// r6 - s02` // c2r0
	// r7 - s03` // c3r0
	// r8 - s20` // c2r2
	// r9 - s12` // c1r1
	// r10 - s21` // c3r2

	orr.w r5, r5, r9, lsl #8
	orr.w r6, r6, r8, lsl #16
	orr.w r7, r7, r10, lsl #16
	orr.w r6, r6, r3, lsl #8
	orr.w r7, r7, r0, lsl #8
	orr.w r6, r6, r1, lsl #24
	orr.w r7, r7, r2, lsl #24

	ldmia r12!, {r0-r3}

	//current allocation
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02`| s13`| s20`| s31`
	// r7 - s03`| s10`| s21`| s32`
	// r8 -
	// r9 -
	// r10 -

	eors r0, r4
	eors r1, r5
	eors r2, r6
	eors r3, r7

	//load in, out, len counter
	ldr r12, [sp, #20] // reload to ctx+64
	ldr r4, [sp, #20+4] // in p
	ldr r6, [sp, #20+8] // out p
	ldr r7, [sp, #20+48] // final in_p address at which we break encryption  // argument passed through stack

	//load input, xor keystream and write to output
	ldmia r4!, {r5, r8-r10}

	eors r0, r5
	eor r1, r8
	eor r2, r9
	eor r3, r10

	cmp r4, r7

	str r1, [r6, #4]
	str r2, [r6, #8]
	str r3, [r6, #12]
	str.w r0, [r6], #16

	beq ctr_exit // if in_p == final_p: exit

	ldr r5, [r12, #-52] // ctr, incremented at the beginning of the loop
	str r4, [sp, #20+4] // in p

	tst r5, #0xff000000
	str r6, [sp, #20+8] // out p

	bne ctr_encrypt_block //if (BE)ctr%256!=0

	sub r12, #64 //reset to p, as required by partial_precompute
	b ctr_partial_precompute

ctr_exit:
	add sp, #20+12
	pop {r4-r11,pc}

#endif
