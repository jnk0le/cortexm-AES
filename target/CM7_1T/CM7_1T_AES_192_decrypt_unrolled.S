// uses backward expanded round key
// LUT loads are splitted to avoid data dependent issuing capability from even/odd DTCM words

.syntax unified
.thumb
.text
//.section .itcm.text, "x"

.align 3
// void CM7_1T_AES_192_decrypt_unrolled(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM7_1T_AES_192_decrypt_unrolled
.type   CM7_1T_AES_192_decrypt_unrolled,%function
CM7_1T_AES_192_decrypt_unrolled:
	push {r2,r4-r11, lr} //stack output pointer

	add r12, r0, #192 // 12 rounds * 16

	movw r14, #:lower16:AES_Td0
	movt r14, #:upper16:AES_Td0

	//load input
	ldm r1, {r4-r7}

	//load initial round key
	ldm r12, {r0-r3}

	//initial addroundkey
	eors r4, r0
	eors r5, r1

	eors r6, r2
	ldr r8, [r12, #-16]!

	eors r7, r3
	ldr r9, [r12, #4]

	//ldrd r8,r9, [r12, #-16]!

	//round 1
	uxtb r0, r4
	ldr r10, [r12, #8]

	uxtb r1, r5
	ldr r11, [r12, #12]

	uxtb r2, r6
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r7
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #16
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #16
	ldr r3, [r14, r3, lsl #2]

	eor r10, r10, r2, ror #16
	uxtb r0, r7, ror #8

	eor r11, r11, r3, ror #16
	uxtb r1, r4, ror #8

	uxtb r2, r5, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #8
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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r5, ror #24

	eor r11, r3
	uxtb r1, r6, ror #24

	uxtb r2, r7, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r4, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12, #-16]!

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4]

	//round 2
	uxtb r0, r4
	ldr r10, [r12, #8]

	uxtb r1, r5
	ldr r11, [r12, #12]

	uxtb r2, r6
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r7
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #16
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #16
	ldr r3, [r14, r3, lsl #2]

	eor r10, r10, r2, ror #16
	uxtb r0, r7, ror #8

	eor r11, r11, r3, ror #16
	uxtb r1, r4, ror #8

	uxtb r2, r5, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #8
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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r5, ror #24

	eor r11, r3
	uxtb r1, r6, ror #24

	uxtb r2, r7, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r4, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12, #-16]!

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4]

	//round 3
	uxtb r0, r4
	ldr r10, [r12, #8]

	uxtb r1, r5
	ldr r11, [r12, #12]

	uxtb r2, r6
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r7
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #16
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #16
	ldr r3, [r14, r3, lsl #2]

	eor r10, r10, r2, ror #16
	uxtb r0, r7, ror #8

	eor r11, r11, r3, ror #16
	uxtb r1, r4, ror #8

	uxtb r2, r5, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #8
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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r5, ror #24

	eor r11, r3
	uxtb r1, r6, ror #24

	uxtb r2, r7, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r4, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12, #-16]!

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4]

	//round 4
	uxtb r0, r4
	ldr r10, [r12, #8]

	uxtb r1, r5
	ldr r11, [r12, #12]

	uxtb r2, r6
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r7
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #16
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #16
	ldr r3, [r14, r3, lsl #2]

	eor r10, r10, r2, ror #16
	uxtb r0, r7, ror #8

	eor r11, r11, r3, ror #16
	uxtb r1, r4, ror #8

	uxtb r2, r5, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #8
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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r5, ror #24

	eor r11, r3
	uxtb r1, r6, ror #24

	uxtb r2, r7, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r4, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12, #-16]!

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4]

	//round 5
	uxtb r0, r4
	ldr r10, [r12, #8]

	uxtb r1, r5
	ldr r11, [r12, #12]

	uxtb r2, r6
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r7
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #16
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #16
	ldr r3, [r14, r3, lsl #2]

	eor r10, r10, r2, ror #16
	uxtb r0, r7, ror #8

	eor r11, r11, r3, ror #16
	uxtb r1, r4, ror #8

	uxtb r2, r5, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #8
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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r5, ror #24

	eor r11, r3
	uxtb r1, r6, ror #24

	uxtb r2, r7, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r4, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12, #-16]!

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4]

	//round 6
	uxtb r0, r4
	ldr r10, [r12, #8]

	uxtb r1, r5
	ldr r11, [r12, #12]

	uxtb r2, r6
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r7
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #16
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #16
	ldr r3, [r14, r3, lsl #2]

	eor r10, r10, r2, ror #16
	uxtb r0, r7, ror #8

	eor r11, r11, r3, ror #16
	uxtb r1, r4, ror #8

	uxtb r2, r5, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #8
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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r5, ror #24

	eor r11, r3
	uxtb r1, r6, ror #24

	uxtb r2, r7, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r4, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12, #-16]!

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4]

	//round 7
	uxtb r0, r4
	ldr r10, [r12, #8]

	uxtb r1, r5
	ldr r11, [r12, #12]

	uxtb r2, r6
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r7
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #16
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #16
	ldr r3, [r14, r3, lsl #2]

	eor r10, r10, r2, ror #16
	uxtb r0, r7, ror #8

	eor r11, r11, r3, ror #16
	uxtb r1, r4, ror #8

	uxtb r2, r5, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #8
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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r5, ror #24

	eor r11, r3
	uxtb r1, r6, ror #24

	uxtb r2, r7, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r4, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12, #-16]!

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4]

	//round 8
	uxtb r0, r4
	ldr r10, [r12, #8]

	uxtb r1, r5
	ldr r11, [r12, #12]

	uxtb r2, r6
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r7
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #16
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #16
	ldr r3, [r14, r3, lsl #2]

	eor r10, r10, r2, ror #16
	uxtb r0, r7, ror #8

	eor r11, r11, r3, ror #16
	uxtb r1, r4, ror #8

	uxtb r2, r5, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #8
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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r5, ror #24

	eor r11, r3
	uxtb r1, r6, ror #24

	uxtb r2, r7, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r4, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12, #-16]!

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4]

	//round 9
	uxtb r0, r4
	ldr r10, [r12, #8]

	uxtb r1, r5
	ldr r11, [r12, #12]

	uxtb r2, r6
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r7
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #16
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #16
	ldr r3, [r14, r3, lsl #2]

	eor r10, r10, r2, ror #16
	uxtb r0, r7, ror #8

	eor r11, r11, r3, ror #16
	uxtb r1, r4, ror #8

	uxtb r2, r5, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #8
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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r5, ror #24

	eor r11, r3
	uxtb r1, r6, ror #24

	uxtb r2, r7, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r4, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12, #-16]!

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4]

	//round 10
	uxtb r0, r4
	ldr r10, [r12, #8]

	uxtb r1, r5
	ldr r11, [r12, #12]

	uxtb r2, r6
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r7
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #16
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #16
	ldr r3, [r14, r3, lsl #2]

	eor r10, r10, r2, ror #16
	uxtb r0, r7, ror #8

	eor r11, r11, r3, ror #16
	uxtb r1, r4, ror #8

	uxtb r2, r5, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #8
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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r5, ror #24

	eor r11, r3
	uxtb r1, r6, ror #24

	uxtb r2, r7, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r4, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12, #-16]!

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4]

	//round 11
	uxtb r0, r4
	ldr r10, [r12, #8]

	uxtb r1, r5
	ldr r11, [r12, #12]

	uxtb r2, r6
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r7
	ldr r1, [r14, r1, lsl #2]

	eor r8, r8, r0, ror #16
	ldr r2, [r14, r2, lsl #2]

	eor r9, r9, r1, ror #16
	ldr r3, [r14, r3, lsl #2]

	eor r10, r10, r2, ror #16
	uxtb r0, r7, ror #8

	eor r11, r11, r3, ror #16
	uxtb r1, r4, ror #8

	uxtb r2, r5, ror #8
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #8
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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r5, ror #24

	eor r11, r3
	uxtb r1, r6, ror #24

	uxtb r2, r7, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r4, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12, #-16]!

	movw r14, #:lower16:AES_inv_sbox
	movt r14, #:upper16:AES_inv_sbox

	eor r7, r11, r3, ror #24
	//final round
	ldr r9, [r12, #4]

	uxtb r0, r4
	ldr r10, [r12, #8]

	uxtb r1, r5
	ldr r11, [r12, #12]

	uxtb r2, r6
	ldrb r0, [r14, r0]

	uxtb r3, r7
	ldrb r1, [r14, r1]

	eor r8, r0
	ldrb r2, [r14, r2]

	eor r9, r1
	ldrb r3, [r14, r3]

	eor r10, r2
	uxtb r0, r7, ror #8

	eor r11, r3
	uxtb r1, r4, ror #8

	uxtb r2, r5, ror #8
	ldrb r0, [r14, r0]

	uxtb r3, r6, ror #8
	ldrb r1, [r14, r1]

	eor r8, r8, r0, lsl #8
	ldrb r2, [r14, r2]

	eor r9, r9, r1, lsl #8
	ldrb r3, [r14, r3]

	eor r10, r10, r2, lsl #8
	uxtb r0, r6, ror #16

	eor r11, r11, r3, lsl #8
	uxtb r1, r7, ror #16

	uxtb r2, r4, ror #16
	ldrb r0, [r14, r0]

	uxtb r3, r5, ror #16
	ldrb r1, [r14, r1]

	eor r8, r8, r0, lsl #16
	ldrb r2, [r14, r2]

	eor r9, r9, r1, lsl #16
	ldrb r3, [r14, r3]

	eor r10, r10, r2, lsl #16
	uxtb r0, r5, ror #24

	eor r11, r11, r3, lsl #16
	uxtb r1, r6, ror #24

	uxtb r2, r7, ror #24
	ldrb r0, [r14, r0]

	uxtb r3, r4, ror #24
	ldrb r1, [r14, r1]

	eor r0, r8, r0, lsl #24
	ldrb r2, [r14, r2]

	eor r1, r9, r1, lsl #24
	ldrb r3, [r14, r3]

	eor r2, r10, r2, lsl #24
	ldr r5, [sp], #4 //load output pointer and clear stack

	eor r3, r11, r3, lsl #24
	ldr r4, [sp], #4 // pop early to pop even number of registers later

	stmia r5!, {r0-r3}

	pop {r5-r11, pc}
