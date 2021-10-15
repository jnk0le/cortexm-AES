.syntax unified
.thumb
.text

.align 3
// void CM3_1T_AES_256_encrypt_unrolled(const uint8_t* rk, const uint8_t* in, uint8_t* out) {
.global CM3_1T_AES_256_encrypt_unrolled
.type   CM3_1T_AES_256_encrypt_unrolled,%function
CM3_1T_AES_256_encrypt_unrolled:
#if __ARM_ARCH_7M__
	push {r2,r4-r11,lr} // stack output pointer

	mov.w r12, r0  // align following code to 4 bytes

	movw r14, #:lower16:AES_Te2
	movt r14, #:upper16:AES_Te2

	//load input
	//ldmia r1!, {r4-r7}
	ldr r4, [r1, #0]
	ldr r5, [r1, #4]
	ldr r6, [r1, #8]
	ldr r7, [r1, #12]

	//load key
	//ldmia r12!, {r0-r3}
	ldr r0, [r12, #0]
	ldr r1, [r12, #4]
	ldr r2, [r12, #8]
	ldr r3, [r12, #12]

	//initial addroundkey
	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

	//round 1
	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r8, [r12, #16]
	ldr r9, [r12, #20]
	ldr r10, [r12, #24]
	ldr r11, [r12, #28]
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
	eor r2, r2, r5, ror #24
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1
	eor r6, r10, r2
	eor r7, r11, r3

	//round 2
	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r8, [r12, #32]
	ldr r9, [r12, #36]
	ldr r10, [r12, #40]
	ldr r11, [r12, #44]
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
	eor r2, r2, r5, ror #24
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1
	eor r6, r10, r2
	eor r7, r11, r3

	//round 3
	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r8, [r12, #48]
	ldr r9, [r12, #52]
	ldr r10, [r12, #56]
	ldr r11, [r12, #60]
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
	eor r2, r2, r5, ror #24
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1
	eor r6, r10, r2
	eor r7, r11, r3

	//round 4
	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r8, [r12, #64]
	ldr r9, [r12, #68]
	ldr r10, [r12, #72]
	ldr r11, [r12, #76]
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
	eor r2, r2, r5, ror #24
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1
	eor r6, r10, r2
	eor r7, r11, r3

	//round 5
	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r8, [r12, #80]
	ldr r9, [r12, #84]
	ldr r10, [r12, #88]
	ldr r11, [r12, #92]
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
	eor r2, r2, r5, ror #24
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1
	eor r6, r10, r2
	eor r7, r11, r3

	//round 6
	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r8, [r12, #96]
	ldr r9, [r12, #100]
	ldr r10, [r12, #104]
	ldr r11, [r12, #108]
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
	eor r2, r2, r5, ror #24
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1
	eor r6, r10, r2
	eor r7, r11, r3

	//round 7
	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r8, [r12, #112]
	ldr r9, [r12, #116]
	ldr r10, [r12, #120]
	ldr r11, [r12, #124]
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
	eor r2, r2, r5, ror #24
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1
	eor r6, r10, r2
	eor r7, r11, r3

	//round 8
	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r8, [r12, #128]
	ldr r9, [r12, #132]
	ldr r10, [r12, #136]
	ldr r11, [r12, #140]
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
	eor r2, r2, r5, ror #24
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1
	eor r6, r10, r2
	eor r7, r11, r3

	//round 9
	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r8, [r12, #144]
	ldr r9, [r12, #148]
	ldr r10, [r12, #152]
	ldr r11, [r12, #156]
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
	eor r2, r2, r5, ror #24
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1
	eor r6, r10, r2
	eor r7, r11, r3

	//round 10
	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r8, [r12, #160]
	ldr r9, [r12, #164]
	ldr r10, [r12, #168]
	ldr r11, [r12, #172]
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
	eor r2, r2, r5, ror #24
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1
	eor r6, r10, r2
	eor r7, r11, r3

	//round 11
	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r8, [r12, #176]
	ldr r9, [r12, #180]
	ldr r10, [r12, #184]
	ldr r11, [r12, #188]
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
	eor r2, r2, r5, ror #24
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1
	eor r6, r10, r2
	eor r7, r11, r3

	//round 12
	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r8, [r12, #192]
	ldr r9, [r12, #196]
	ldr r10, [r12, #200]
	ldr r11, [r12, #204]
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
	eor r2, r2, r5, ror #24
	eor r3, r3, r6, ror #24

	eor r4, r8, r0
	eor r5, r9, r1
	eor r6, r10, r2
	eor r7, r11, r3

	//round 13
	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r8, [r12, #208]
	ldr r9, [r12, #212]
	ldr r10, [r12, #216]
	ldr r11, [r12, #220]
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
	ldr r4, [sp], #4 // load output pointer and clear stack
	ldr r14, [r12, #224]
	ldr r5, [r12, #228]
	ldr r6, [r12, #232]
	ldr r7, [r12, #236]

	bfi r8, r0, #16, #8
	bfi r9, r1, #16, #8
	bfi r10, r2, #16, #8
	bfi r11, r3, #16, #8

	eor r0, r14, r8, ror #8
	eor r1, r5, r9, ror #8
	eor r2, r6, r10, ror #8
	eor r3, r7, r11, ror #8

	str r0, [r4, #0]
	str r1, [r4, #4]
	str r2, [r4, #8]
	str r3, [r4, #12]

	pop {r4-r11,pc}
#else
	b . //crash in case the function was called on thumb1 core
#endif
