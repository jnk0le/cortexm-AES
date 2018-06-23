// uses backward expanded round key
// LUT loads are splitted to avoid data dependent issuing capability from even/odd DTCM words

.syntax unified
.thumb
.text
//.section .itcm.text, "x"

.align 3
// void CM7_1T_AES_decrypt_unrolled(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM7_1T_AES_decrypt_unrolled
.type   CM7_1T_AES_decrypt_unrolled,%function
CM7_1T_AES_decrypt_unrolled:
	push {r2,r4-r11, lr} //stack output pointer

	add r12, r0, r3, lsl #4 //rk_end-16 = rk + rounds * 16
	cmp r3, #12

	movw r14, #:lower16:AES_Td0
	movt r14, #:upper16:AES_Td0

	//load input
	ldm r1, {r4-r7}

	//load initial round key
	ldm r12, {r0-r3}

	//initial addroundkey
	itttt vc // use overflow flag since it is never set in above comparison // cannot use al due to gcc errors
	eorvc r4, r0
	eorvc r5, r1

	eorvc r6, r2
	eorvc r7, r3

	// loads that are interleaved with previous round
	//ldrd r8,r9, [r12, #-16]!
	ldr r8, [r12, #-16]!
	ldr r9, [r12, #4]

	blo.w 10f // if rounds < 12
	beq.w 12f // if rounds == 12
	// go forward if rounds > 12

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
	ldr r8, [r12, #-16]! //round 2

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4] //round 2

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
	ldr r8, [r12, #-16]! //round 3/1

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4] //round 3/1

	//round 3/1
12:	uxtb r0, r4
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
	ldr r8, [r12, #-16]! //round 4/2

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4] //round 4/2

	//round 4/2
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
	ldr r8, [r12, #-16]! //round 5/3/1

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4] //round 5/3/1

	//round 5/3/1
10:	uxtb r0, r4
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
	ldr r8, [r12, #-16]! //round 6/4/2

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4] //round 6/4/2

	//round 6/4/2
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
	ldr r8, [r12, #-16]! //round 7/5/3

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4] //round 7/5/3

	//round 7/5/3
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
	ldr r8, [r12, #-16]! //round 8/6/4

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4] //round 8/6/4

	//round 8/6/4
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
	ldr r8, [r12, #-16]! //round 9/7/5

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4] //round 9/7/5

	//round 9/7/5
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
	ldr r8, [r12, #-16]! //round 10/8/6

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4] //round 10/8/6

	//round 10/8/6
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
	ldr r8, [r12, #-16]! //round 11/9/7

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4] //round 11/9/7

	//round 11/9/7
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
	ldr r8, [r12, #-16]! //round 12/10/8

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4] //round 12/10/8

	//round 12/10/8
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
	ldr r8, [r12, #-16]! //round 13/11/9

	eor r7, r11, r3, ror #24
	ldr r9, [r12, #4] //round 13/11/9

	//round 13/11/9
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
	ldr r8, [r12, #-16]! //final round

	movw r14, #:lower16:AES_inv_sbox //final round
	movt r14, #:upper16:AES_inv_sbox //final round

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
	ldr r4, [sp], #4 //load output pointer and clear stack

	eor r3, r11, r3, lsl #24

	stmia r4!, {r0-r3}

	pop {r4-r11, pc}
