// LUT loads are splitted to avoid data dependent issuing capability from even/odd DTCM words

.syntax unified
.thumb
.text
//.section .itcm.text, "x"

.align 3
// void CM7_1T_AES_encrypt_unrolled(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM7_1T_AES_encrypt_unrolled
.type   CM7_1T_AES_encrypt_unrolled,%function
CM7_1T_AES_encrypt_unrolled:
	push {r2, r4-r11,lr} //stack output pointer

	mov r12, r0
	cmp r3, #12

	movw r14, #:lower16:AES_Te2
	movt r14, #:upper16:AES_Te2

	//load input
	ldmia r1!, {r4-r7}

	//load key
	ldmia r12!, {r0-r3}

	//initial addroundkey
	itttt vc // use overflow flag since it is never set in above comparison // cannot use al due to gcc errors
	eorvc r4, r0
	eorvc r5, r1

	eorvc r6, r2
	eorvc r7, r3

	// loads that are interleaved with previous round
	//ldrd r8,r9, [r12], #8
	ldr r8, [r12], #4
	ldr r9, [r12], #4

	beq.w 12f // if rounds == 12
	blo.w 10f // if rounds < 12
	// go forward if rounds > 12

	//round 1
	//ldmia r12!, {r8-r11}
	//ldrd r8,r9, [r12], #8

	uxtb r0, r4
	ldr r10, [r12], #4

	uxtb r1, r5
	ldr r11, [r12], #4

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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r7, ror #24

	eor r11, r3
	uxtb r1, r4, ror #24

	uxtb r2, r5, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12], #4

	eor r7, r11, r3, ror #24
	ldr r9, [r12], #4

	//round 2
	//ldmia r12!, {r8-r11}
	//ldrd r8,r9, [r12], #8

	uxtb r0, r4
	ldr r10, [r12], #4

	uxtb r1, r5
	ldr r11, [r12], #4

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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r7, ror #24

	eor r11, r3
	uxtb r1, r4, ror #24

	uxtb r2, r5, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12], #4

	eor r7, r11, r3, ror #24
	ldr r9, [r12], #4

	//round 3/1
12:	//ldmia r12!, {r8-r11}
	//ldrd r8,r9, [r12], #8

	uxtb r0, r4
	ldr r10, [r12], #4

	uxtb r1, r5
	ldr r11, [r12], #4

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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r7, ror #24

	eor r11, r3
	uxtb r1, r4, ror #24

	uxtb r2, r5, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12], #4

	eor r7, r11, r3, ror #24
	ldr r9, [r12], #4

	//round 4/2
	//ldmia r12!, {r8-r11}
	//ldrd r8,r9, [r12], #8

	uxtb r0, r4
	ldr r10, [r12], #4

	uxtb r1, r5
	ldr r11, [r12], #4

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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r7, ror #24

	eor r11, r3
	uxtb r1, r4, ror #24

	uxtb r2, r5, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12], #4

	eor r7, r11, r3, ror #24
	ldr r9, [r12], #4

	//round 5/3/1
10:	//ldmia r12!, {r8-r11}
	//ldrd r8,r9, [r12], #8

	uxtb r0, r4
	ldr r10, [r12], #4

	uxtb r1, r5
	ldr r11, [r12], #4

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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r7, ror #24

	eor r11, r3
	uxtb r1, r4, ror #24

	uxtb r2, r5, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12], #4

	eor r7, r11, r3, ror #24
	ldr r9, [r12], #4

	//round 6/4/2
	//ldmia r12!, {r8-r11}
	//ldrd r8,r9, [r12], #8

	uxtb r0, r4
	ldr r10, [r12], #4

	uxtb r1, r5
	ldr r11, [r12], #4

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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r7, ror #24

	eor r11, r3
	uxtb r1, r4, ror #24

	uxtb r2, r5, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12], #4

	eor r7, r11, r3, ror #24
	ldr r9, [r12], #4

	//round 7/5/3
	//ldmia r12!, {r8-r11}
	//ldrd r8,r9, [r12], #8

	uxtb r0, r4
	ldr r10, [r12], #4

	uxtb r1, r5
	ldr r11, [r12], #4

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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r7, ror #24

	eor r11, r3
	uxtb r1, r4, ror #24

	uxtb r2, r5, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12], #4

	eor r7, r11, r3, ror #24
	ldr r9, [r12], #4

	//round 8/6/4
	//ldmia r12!, {r8-r11}
	//ldrd r8,r9, [r12], #8

	uxtb r0, r4
	ldr r10, [r12], #4

	uxtb r1, r5
	ldr r11, [r12], #4

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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r7, ror #24

	eor r11, r3
	uxtb r1, r4, ror #24

	uxtb r2, r5, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12], #4

	eor r7, r11, r3, ror #24
	ldr r9, [r12], #4

	//round 9/7/5
	//ldmia r12!, {r8-r11}
	//ldrd r8,r9, [r12], #8

	uxtb r0, r4
	ldr r10, [r12], #4

	uxtb r1, r5
	ldr r11, [r12], #4

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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r7, ror #24

	eor r11, r3
	uxtb r1, r4, ror #24

	uxtb r2, r5, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12], #4

	eor r7, r11, r3, ror #24
	ldr r9, [r12], #4

	//round 10/8/6
	//ldmia r12!, {r8-r11}
	//ldrd r8,r9, [r12], #8

	uxtb r0, r4
	ldr r10, [r12], #4

	uxtb r1, r5
	ldr r11, [r12], #4

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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r7, ror #24

	eor r11, r3
	uxtb r1, r4, ror #24

	uxtb r2, r5, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12], #4

	eor r7, r11, r3, ror #24
	ldr r9, [r12], #4

	//round 11/9/7
	//ldmia r12!, {r8-r11}
	//ldrd r8,r9, [r12], #8

	uxtb r0, r4
	ldr r10, [r12], #4

	uxtb r1, r5
	ldr r11, [r12], #4

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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r7, ror #24

	eor r11, r3
	uxtb r1, r4, ror #24

	uxtb r2, r5, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12], #4

	eor r7, r11, r3, ror #24
	ldr r9, [r12], #4

	//round 12/10/8
	//ldmia r12!, {r8-r11}
	//ldrd r8,r9, [r12], #8

	uxtb r0, r4
	ldr r10, [r12], #4

	uxtb r1, r5
	ldr r11, [r12], #4

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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r7, ror #24

	eor r11, r3
	uxtb r1, r4, ror #24

	uxtb r2, r5, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	ldr r8, [r12], #4

	eor r7, r11, r3, ror #24
	ldr r9, [r12], #4

	//round 13/11/9
	//ldmia r12!, {r8-r11}
	//ldrd r8,r9, [r12], #8

	uxtb r0, r4
	ldr r10, [r12], #4

	uxtb r1, r5
	ldr r11, [r12], #4

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

	eor r8, r0
	ldr r2, [r14, r2, lsl #2]

	eor r9, r1
	ldr r3, [r14, r3, lsl #2]

	eor r10, r2
	uxtb r0, r7, ror #24

	eor r11, r3
	uxtb r1, r4, ror #24

	uxtb r2, r5, ror #24
	ldr r0, [r14, r0, lsl #2]

	uxtb r3, r6, ror #24
	ldr r1, [r14, r1, lsl #2]

	eor r4, r8, r0, ror #24
	ldr r2, [r14, r2, lsl #2]

	eor r5, r9, r1, ror #24
	ldr r3, [r14, r3, lsl #2]

	eor r6, r10, r2, ror #24
	uxtb r1, r4, ror #24

	eor r7, r11, r3, ror #24
	//final round
	uxtb r3, r6, ror #24

	uxtb r0, r7, ror #24
	ldr r9, [r14, r1, lsl #2]

	uxtb r2, r5, ror #24
	ldr r8, [r14, r0, lsl #2]

	uxtb r0, r6, ror #16
	ldr r10, [r14, r2, lsl #2]

	uxtb r1, r7, ror #16
	ldr r11, [r14, r3, lsl #2]

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

	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]

	uxtb r2, r6
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

	bfi r10, r2, #16, #8
	ldr r0, [r12]

	bfi r11, r3, #16, #8
	//ldmia r12, {r0-r3}
	ldr r1, [r12, #4]

	eor r0, r0, r8, ror #8
	ldr r2, [r12, #8]

	eor r1, r1, r9, ror #8
	ldr r3, [r12, #12]

	eor r2, r2, r10, ror #8
	ldr r5, [sp], #4 //load output pointer and clear stack

	eor r3, r3, r11, ror #8
	ldr r4, [sp], #4 // pop early to pop even number of registers later

	stmia r5!, {r0-r3}

	pop {r5-r11,pc}
