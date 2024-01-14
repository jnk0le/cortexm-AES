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

.include "aes/target/CM7_1T_modes/CM7_1T_AES_unrolled.inc"

.syntax unified
.thumb
.text

.balign 8
// void CM7_1T_AES_192_CTR32_enc_unrolled(void* ctx, uint8_t* data_in, uint8_t* data_out, uint32_t blocks_cnt) {
.global CM7_1T_AES_192_CTR32_enc_unrolled
.type   CM7_1T_AES_192_CTR32_enc_unrolled,%function
CM7_1T_AES_192_CTR32_enc_unrolled:
#if __ARM_ARCH_7EM__
	mov.w r12, r0 // align
	add r3, r1, r3, lsl #4 // in_p + cnt*16

	push {r2-r11,lr} // push data_out, data_in_end

	mov r11, r1
	sub sp, #24

	movw r14, #:lower16:AES_Te2
	movt r14, #:upper16:AES_Te2

	// sp
	// +0  - precomputed_y0
	// +4  - precomputed_y1
	// +8  - precomputed_y2
	// +12 - precomputed_y3
	// +16 - precomputed_x0

	// +20 - align (unused)

	// +24 - data_out_p
	// +28 - data_in_end (final ptr)

	// stacked registers

	// global allocation
	// r11 - data_in_p
	// r12 - ctx
	// r14 - Te2

ctr_partial_precompute:
	//load from ctx nonce in r0-r3, key in r4-r7
	ldm r12, {r0-r7}
	//ldrd r0,r1, [r12, #0]
	//ldrd r2,r3, [r12, #8]
	//ldrd r4,r5, [r12, #16]
	//ldrd r6,r7, [r12, #24]

	//initial addroundkey
	eors.w r0, r4 // must align here after ldm
	eors.w r1, r5 // must align here after ldm

	eors r2, r6
	eors r3, r7

	//s33 is lowest byte of counter, can't be precomputed

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

	// start from col 1
	uxtb.w r5, r3, ror #16
	lsrs r4, r0, #24

	uxtb r6, r1
	ldr.w r10, [r14, r4, lsl #2]

	//current alloctaion
	// r0 - s00 | s10 | s20 |
	// r1 -     | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 |     |
	// r4 -
	// r5 - s23 // c1
	// r6 - s01 // c1 ror16
	// r7 -
	// r8 -
	// r9 -
	// r10 - s30T // c1 ror24

	uxtb r4, r0
	ldr.w r5, [r14, r5, lsl #2]

	uxtb r7, r2
	ldr.w r9, [r14, r6, lsl #2]

	//current alloctaion
	// r0 -     | s10 | s20 |
	// r1 -     | s11 | s21 | s31
	// r2 -     | s12 | s22 | s32
	// r3 - s03 | s13 |     |
	// r4 - s00 // c0 ror16
	// r5 - s23T // c1
	// r6 -
	// r7 - s02 // c2 ror16
	// r8 -
	// r9 - s01T // c1 ror16
	// r10 - s30T // c1 ror24

	uxtb.w r6, r2, ror #16
	ldr.w r4, [r14, r4, lsl #2]

	uxtb.w r8, r1, ror #8
	eor.w r5, r5, r10, ror #24

	//current alloctaion
	// r0 -     | s10 | s20 |
	// r1 -     |     | s21 | s31
	// r2 -     | s12 |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s00T // c0 ror16
	// r5 - s23T ^ s30T // c1
	// r6 - s22 // c0
	// r7 - s02 // c2 ror16
	// r8 - s11 // c0 ror8
	// r9 - s01T // c1 ror16
	// r10 -

	eor.w r5, r5, r9, ror #16
	ldr.w r10, [r14, r6, lsl #2]

	uxtb.w r9, r2, ror #8
	ldr.w r8, [r14, r8, lsl #2]

	//current alloctaion
	// r0 -     | s10 | s20 |
	// r1 -     |     | s21 | s31
	// r2 -     |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s00T // c0 ror16
	// r5 - s23T ^ s30T ^ s01T // c1
	// r6 -
	// r7 - s02 // c2 ror16
	// r8 - s11T // c0 ror8
	// r9 - s12 // c1 ror8
	// r10 - s22T // c0

	eor.w r4, r10, r4, ror #16
	ldr.w r10, [r14, r7, lsl #2]

	uxtb.w r6, r0, ror #16
	ldr.w r9, [r14, r9, lsl #2]

	//current alloctaion
	// r0 -     | s10 |     |
	// r1 -     |     | s21 | s31
	// r2 -     |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s22T ^ s00T // c0
	// r5 - s23T ^ s30T ^ s01T // c1
	// r6 - s20 // c2
	// r7 -
	// r8 - s11T // c0 ror8
	// r9 - s12T // c1 ror8
	// r10 - s02T // c2 ror16

	uxtb.w r7, r3, ror #8
	eor.w r4, r4, r8, ror #8

	uxtb.w r8, r1, ror #16
	eor.w r5, r5, r9, ror #8

	//current alloctaion
	// r0 -     | s10 |     |
	// r1 -     |     |     | s31
	// r2 -     |     |     | s32
	// r3 - s03 |     |     |
	// r4 - col 0
	// r5 - col 1
	// r6 - s20 // c2
	// r7 - s13 // c2 ror8
	// r8 - s21 // c3
	// r9 -
	// r10 - s02T // c2 ror16

	lsrs r1, #24
	ldr.w r9, [r14, r6, lsl #2]

	uxtb r6, r3
	ldr.w r8, [r14, r8, lsl #2]

	//current alloctaion
	// r0 -     | s10 |     |
	// r1 - s31 // c2 ror24
	// r2 -     |     |     | s32
	// r3 -
	// r4 - col 0
	// r5 - col 1
	// r6 - s03 // c3 ror16
	// r7 - s13 // c2 ror8
	// r8 - s21T // c3
	// r9 - s20T // c2
	// r10 - s02T // c2 ror16

	eor.w r9, r9, r10, ror #16
	ldr.w r10, [r14, r7, lsl #2]

	lsrs r7, r2, #24
	ldr.w r6, [r14, r6, lsl #2]

	//current alloctaion
	// r0 -     | s10 |     |
	// r1 - s31 // c2 ror24
	// r2 -
	// r3 -
	// r4 - col 0
	// r5 - col 1
	// r6 - s03T // c3 ror16
	// r7 - s32 // c3 ror24
	// r8 - s21T // c3
	// r9 - s20T ^ s02T // c2
	// r10 - s13T // c2 ror8

	eor.w r9, r9, r10, ror #8
	ldr.w r7, [r14, r7, lsl #2]

	eor.w r8, r8, r6, ror #16
	ldr.w r10, [r14, r1, lsl #2]

	//current alloctaion
	// r0 -     | s10 |     |
	// r1 -
	// r2 -
	// r3 -
	// r4 - col 0
	// r5 - col 1
	// r6 -
	// r7 - s32T // c3 ror24
	// r8 - s21T ^ s03T // c3
	// r9 - s20T ^ s02T ^ s13T // c2
	// r10 - s31T // c2 ror24

	uxtb.w r6, r0, ror #8
	eor.w r8, r8, r7, ror #24

	ldrd r0,r1, [r12, #32]
	ldrd r2,r3, [r12, #40]

	//current alloctaion
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 - col 0
	// r5 - col 1
	// r6 - s10 // c3 ror8
	// r7 -
	// r8 - s21T ^ s03T ^ s32T // c3
	// r9 - s20T ^ s02T ^ s13T // c2
	// r10 - s31T // c2 ror24

	eor.w r7, r9, r10, ror #24 // c2 in r7
	ldr.w r6, [r14, r6, lsl #2]

	eors r0, r4
	str r0, [sp, #16]

	eor.w r6, r8, r6, ror #8
	eors r1, r5

	eors r2, r7
	eors r3, r6

	//row 0 can't be precomputed anymore

	// r0 - x
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33

	// rotation after Te2
	// xor   16 |  8  |  0  |  24

	// c0 -      ^ s11T ^ s22T ^ s33T
	// c1 - s01T ^ s12T ^ s23T ^
	// c2 - s02T ^ s13T ^      ^ s31T
	// c3 - s03T ^      ^ s21T ^ s32T

	//round 2
	uxtb.w r10, r2, ror #16
	lsrs r5, r1, #24

	uxtb r4, r1
	ldr.w r8, [r14, r5, lsl #2]

	//current alloctaion
	// r0 -
	// r1 -     | s11 | s21 |
	// r2 - s02 | s12 |     | s32
	// r3 - s03 | s13 | s23 | s33
	// r4 - s01 // c1 ror16
	// r5 -
	// r6 -
	// r7 -
	// r8 - s31T // c2 ror24
	// r9 -
	// r10 - s22 // c0

	uxtb.w r9, r1, ror #8
	ldr.w r10, [r14, r10, lsl #2]

	lsrs r0, r3, #24
	ldr.w r4, [r14, r4, lsl #2]

	//current alloctaion
	// r0 - s33 // c0 ror24
	// r1 -     |     | s21 |
	// r2 - s02 | s12 |     | s32
	// r3 - s03 | s13 | s23 |
	// r4 - s01T // c1 ror16
	// r5 -
	// r6 -
	// r7 -
	// r8 - s31T // c2 ror24
	// r9 - s11 // c0 ror8
	// r10 - s22T // c0

	uxtb r6, r2
	ldr.w r9, [r14, r9, lsl #2]

	uxtb.w r5, r3, ror #16
	ldr.w r0, [r14, r0, lsl #2]

	//current alloctaion
	// r0 - s33T // c0 ror24
	// r1 -     |     | s21 |
	// r2 -     | s12 |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s01T // c1 ror16
	// r5 - s23 // c1
	// r6 - s02 // c2 ror16
	// r7 -
	// r8 - s31T // c2 ror24
	// r9 - s11T // c0 ror8
	// r10 - s22T // c0

	eor.w r10, r10, r9, ror #8
	ldr.w r9, [r14, r6, lsl #2]

	uxtb.w r7, r2, ror #8
	ldr.w r5, [r14, r5, lsl #2]

	//current alloctaion
	// r0 - s33T // c0 ror24
	// r1 -     |     | s21 |
	// r2 -     |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s01T // c1 ror16
	// r5 - s23T // c1
	// r6 -
	// r7 - s12 // c1 ror8
	// r8 - s31T // c2 ror24
	// r9 - s02T // c2 ror16
	// r10 - s22T ^ s11T // c0

	uxtb.w r6, r3, ror #8
	eor.w r8, r8, r9, ror #24 // effectively ror #16 after the ror #24

	eor.w r5, r5, r4, ror #16
	ldr.w r9, [r14, r7, lsl #2]

	//current alloctaion
	// r0 - s33T // c0 ror24
	// r1 -     |     | s21 |
	// r2 -     |     |     | s32
	// r3 - s03 |     |     |
	// r4 -
	// r5 - s23T ^ s01T // c1
	// r6 - s13 // c2 ror8
	// r7 -
	// r8 - s31T ^ s02T // c2 ror24
	// r9 - s12T // c1 ror8
	// r10 - s22T ^ s11T // c0

	uxtb r7, r3
	eor.w r4, r10, r0, ror #24

	lsrs r2, #24
	ldr.w r6, [r14, r6, lsl #2]

	//current alloctaion
	// r0 -
	// r1 -     |     | s21 |
	// r2 - s32 // c3 ror24
	// r3 -
	// r4 - col 0
	// r5 - s23T ^ s01T // c1
	// r6 - s13T // c2 ror8
	// r7 - s03 // c3 ror16
	// r8 - s31T ^ s02T // c2 ror24
	// r9 - s12T // c1 ror8
	// r10 -

	uxtb.w r10, r1, ror #16
	ldr.w r7, [r14, r7, lsl #2]

	eor.w r5, r5, r9, ror #8
	ldr.w r9, [r14, r2, lsl #2]

	ldrd r0,r1, [r12, #48]
	ldrd r2,r3, [r12, #56]

	//current alloctaion
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 - rk[2]
	// r3 - rk[3]
	// r4 - col 0
	// r5 - col 1
	// r6 - s13T // c2 ror8
	// r7 - s03T // c3 ror16
	// r8 - s31T ^ s02T // c2 ror24
	// r9 - s32T // c3 ror24
	// r10 - s21 // c3

	eors r4, r0
	ldr.w r10, [r14, r10, lsl #2]

	eors r5, r1
	eor.w r6, r2, r6, ror #8

	//current alloctaion
	// r0 -
	// r1 -
	// r2 -
	// r3 - rk[3]
	// r4 - col 0 ^ rk[0]
	// r5 - col 1 ^ rk[1]
	// r6 - rk[2] ^ s13T // c2
	// r7 - s03T // c3 ror16
	// r8 - s31T ^ s02T // c2 ror24
	// r9 - s32T // c3 ror24
	// r10 - s21T // c3

	eor.w r7, r10, r7, ror #16
	ldr r0, [r12, #16+12] //preload key[3]

	eor.w r6, r6, r8, ror #24
	ldr r1, [r12, #12] //preload ctr[3]

	//current alloctaion
	// r0 - key[3]
	// r1 - ctr[3]
	// r2 -
	// r3 - rk[3]
	// r4 - col 0 ^ rk[0]
	// r5 - col 1 ^ rk[1]
	// r6 - col 2 ^ rk[2]
	// r7 - s21T ^ s03T // c3
	// r8 -
	// r9 - s32T // c3 ror24
	// r10 -

	eor.w r7, r7, r9, ror #24
	pld.w [r11, #0] // wasted slot, preload in case data is still in external memory

	eors.w r7, r3
	eors.w r0, r1

	//stm.w sp, {r4-r7}
	strd r4,r5, [sp, #0]
	strd r6,r7, [sp, #8]

ctr_encrypt_block:
	//expect ctr[3] in r1
	//expect key[3]^ctr[3] in r0

	//round 1
	lsrs r0, #24
	ldr r2, [sp, #16] // precomputed_x0

	rev r1, r1
	ldr r0, [r14, r0, lsl #2]

	adds r1, #1
	ldr r4, [sp, #0] // precomputed_y0

	eor.w r2, r2, r0, ror #24
	ldr r5, [sp, #4] // precomputed_y1

	rev r1, r1
	ldr r6, [sp, #8] // precomputed_y2

	//round 2
	uxtb r0, r2
	str.w r1, [r12, #12]

	lsrs r1, r2, #24
	ldr r7, [sp, #12] // precomputed_y3

	uxtb r3, r2, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r2, r2, ror #16
	ldr r1, [r14, r1, lsl #2]

	eor.w r0, r4, r0, ror #16
	ldr r3, [r14, r3, lsl #2]

	eor.w r1, r5, r1, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor.w r3, r7, r3, ror #8
	eors r2, r6

	// r0 - s00 | s10 | s20 | s30
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33

	// rotation after Te2
	// xor   16 |  8  |  0  |  24

	// r0 - s00T ^ s11T ^ s22T ^ s33T
	// r1 - s01T ^ s12T ^ s23T ^ s30T
	// r2 - s02T ^ s13T ^ s20T ^ s31T
	// r3 - s03T ^ s10T ^ s21T ^ s32T

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
	// r0 - s00 | s10 | s20 | s30
	// r1 - s01 | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 | s23 | s33

	//final
	// r4 - s00`| s11`| s22`| s33`
	// r5 - s01`| s12`| s23`| s30`
	// r6 - s02`| s13`| s20`| s31`
	// r7 - s03`| s10`| s21`| s32`

	// start from col 1
	uxtb r8, r3, ror #16
	lsrs r4, r0, #24

	uxtb r5, r1
	ldrb.w r9, [r14, r4, lsl #2]

	//current alloctaion
	// r0 - s00 | s10 | s20 |
	// r1 -     | s11 | s21 | s31
	// r2 - s02 | s12 | s22 | s32
	// r3 - s03 | s13 |     | s33
	// r4 -
	// r5 - s01 //r0c1
	// r6 -
	// r7 -
	// r8 - s23 //r2c1
	// r9 - s30` //r3c1
	// r10 -

	uxtb.w r10, r2, ror #8
	ldrb.w r8, [r14, r8, lsl #2]

	uxtb.w r7, r2, ror #16
	ldrb.w r5, [r14, r5, lsl #2]

	//current alloctaion
	// r0 - s00 | s10 | s20 |
	// r1 -     | s11 | s21 | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     | s33
	// r4 -
	// r5 - s01` //r0c1
	// r6 -
	// r7 - s22 //r2c0
	// r8 - s23` //r2c1
	// r9 - s30` //r3c1
	// r10 - s12 //r1c1

	lsrs r6, r3, #24
	ldrb.w r10, [r14, r10, lsl #2]

	orr.w r8, r8, r9, lsl #8
	ldrb.w r6, [r14, r6, lsl #2]

	//current alloctaion
	// r0 -     | s10 | s20 |
	// r1 -     | s11 | s21 | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 -
	// r5 - s01` //r0c1
	// r6 - s33` //r3c0
	// r7 - s22 //r2c0
	// r8 - s23` | s30` //c1 upper
	// r9 -
	// r10 - s12` //r1c1

	uxtb.w r9, r1, ror #8
	ldrb.w r7, [r14, r7, lsl #2]

	uxtb r4, r0
	orr.w r5, r5, r10, lsl #8

	//current alloctaion
	// r0 -     | s10 | s20 |
	// r1 -     |     | s21 | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s00 //r0c0
	// r5 - s01` | s12` //c1 bottom
	// r6 - s33` //r3c0
	// r7 - s22` //r2c0
	// r8 - s23` | s30` //c1 upper
	// r9 - s11 //r1c0
	// r10 -

	orr.w r10, r7, r6, lsl #8
	ldrb.w r9, [r14, r9, lsl #2]

	uxtb.w r7, r0, ror #16
	ldrb.w r4, [r14, r4, lsl #2]

	//current alloctaion
	// r0 -     | s10 |     |
	// r1 -     |     | s21 | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 - s00` //r0c0
	// r5 - s01` | s12` //c1 bottom
	// r6 -
	// r7 - s20 //r2c2
	// r8 - s23` | s30` //c1 upper
	// r9 - s11` //r1c0
	// r10 - s22` | s33` //c0 upper

	uxtb r6, r1, ror #16
	orr.w r5, r5, r8, lsl #16

	orr.w r9, r4, r9, lsl #8
	ldrb.w r7, [r14, r7, lsl #2]

	//current alloctaion
	// r0 -     | s10 |     |
	// r1 -     |     |     | s31
	// r2 - s02 |     |     | s32
	// r3 - s03 | s13 |     |
	// r4 -
	// r5 - col 1
	// r6 - s21 //r2c3
	// r7 - s20` //r2c2
	// r8 -
	// r9 - s00` | s11` //c0 bottom
	// r10 - s22` | s33` //c0 upper

	lsrs r1, #24 // cant .n above
	ldrb.w r8, [r14, r6, lsl #2]

	orr.w r4, r9, r10, lsl #16
	lsrs r6, r2, #24

	//current alloctaion
	// r0 -     | s10 |     |
	// r1 - s31 //r3c2
	// r2 - s02 |     |     |
	// r3 - s03 | s13 |     |
	// r4 - col 0
	// r5 - col 1
	// r6 - s32 //r3c3
	// r7 - s20` //r2c2
	// r8 - s21` //r2c3
	// r9 -
	// r10 -

	uxtb.w r10, r3, ror #8
	ldrb.w r1, [r14, r1, lsl #2]

	uxtb r2, r2
	ldrb.w r6, [r14, r6, lsl #2]

	//current alloctaion
	// r0 -     | s10 |     |
	// r1 - s31` //r3c2
	// r2 - s02 //r0c2
	// r3 - s03 |     |     |
	// r4 - col 0
	// r5 - col 1
	// r6 - s32` //r3c3
	// r7 - s20` //r2c2
	// r8 - s21` //r2c3
	// r9 -
	// r10 - s13 //r1c2

	uxtb r3, r3// cant .n below
	ldrb.w r10, [r14, r10, lsl #2]

	orr.w r9, r7, r1, lsl #8
	ldrb.w r7, [r14, r2, lsl #2]

	//current alloctaion
	// r0 -     | s10 |     |
	// r1 -
	// r2 -
	// r3 - s03 //r0c3
	// r4 - col 0
	// r5 - col 1
	// r6 - s32` //r3c3
	// r7 - s02` //r0c2
	// r8 - s21` //r2c3
	// r9 - s20` | s31` //c2 upper
	// r10 - s13` //r1c2

	orr.w r8, r8, r6, lsl #8
	ldrb.w r6, [r14, r3, lsl #2]

	uxtb.w r3, r0, ror #8
	orr.w r10, r7, r10, lsl #8

	ldrd r0,r1, [r12, #208]

	//current alloctaion
	// r0 - rk[0]
	// r1 - rk[1]
	// r2 -
	// r3 - s10 //r1c3
	// r4 - col 0
	// r5 - col 1
	// r6 - s03` //r0c3
	// r7 -
	// r8 - s21` | s32` //c3 upper
	// r9 - s20` | s31` //c2 upper
	// r10 - s02` | s13` //c2 bottom

	eors r0, r4
	ldrb.w r3, [r14, r3, lsl #2]

	orr.w r4, r10, r9, lsl #16
	eors r5, r1

	ldrd r1,r2, [r12, #216]

	//current alloctaion
	// r0 - rk[0] ^ col 0
	// r1 - rk[2]
	// r2 - rk[3]
	// r3 - s10 //r1c3
	// r4 - col 2
	// r5 - rk[1] ^ col 1
	// r6 - s03` //r0c3
	// r7 -
	// r8 - s21` | s32` //c3 upper
	// r9 -
	// r10 -

	eor.w r3, r6, r3, lsl #8
	ldr.w r7, [r11], #4

	eors r4, r1
	ldr.w r1, [r11], #4

	//current alloctaion
	// r0 - rk[0] ^ col 0
	// r1 - in[1]
	// r2 - rk[3]
	// r3 - s03` | s10` //c3 bottom
	// r4 - rk[2] ^ col 2
	// r5 - rk[1] ^ col 1
	// r6 -
	// r7 - in[0]
	// r8 - s21` | s32` //c3 upper
	// r9 -
	// r10 -

	eors r0, r7
	ldr.w r10, [sp, #28] // final in_p address at which we break encryption

	eor.w r3, r3, r8, lsl #16
	ldr.w r6, [r11], #4

	//current alloctaion
	// r0 - out[0]
	// r1 - in[1]
	// r2 - rk[3]
	// r3 - col 3
	// r4 - rk[2] ^ col 2
	// r5 - rk[1] ^ col 1
	// r6 - in[2]
	// r7 -
	// r8 -
	// r9 -
	// r10 - data_in_end

	eors.w r6, r4
	ldr.w r7, [r11], #4

	cmp r10, r11 // cmp at least 3 cycles ahead
	ldr.w r4, [sp, #24] // out p

	//current alloctaion
	// r0 - out[0]
	// r1 - in[1]
	// r2 - rk[3]
	// r3 - col 3
	// r4 - out_p
	// r5 - rk[1] ^ col 1
	// r6 - out[2]
	// r7 - in[3]
	// r8 -
	// r9 -
	// r10 -

	eor.w r3, r2
	eor.w r5, r1

	eor.w r7, r3
	str.w r0, [r4], #4

	//current alloctaion
	// r0 -
	// r1 -
	// r2 -
	// r3 -
	// r4 - out_p
	// r5 - out[1]
	// r6 - out[2]
	// r7 - out[3]
	// r8 -
	// r9 -
	// r10 -

	ldr r1, [r12, #12] // ctr, incremented at the beginning of the loop
	beq ctr_exit //if in_p == final_p: exit

	lsrs r2, r1, #24 // test top byte for zero, r2 discarded, can be reused but no gain anyway
	ldr r0, [r12, #16+12] // load key[3]

	str r5, [r4], #4
	eor.w r0, r1 // key[3]^ctr[3] to relax round 1 latency

	strd r6,r7, [r4], #8

	str r4, [sp, #24] // out p
	bne.w ctr_encrypt_block //if (BE)ctr%256!=0

	b.w ctr_partial_precompute

ctr_exit:
	add sp, #24+8
	str r5, [r4] // store last block
	strd r6,r7, [r4, #4]
	pop {r4-r11,pc}
#else
	b . //crash in case the function was called on thumb1 core
#endif
