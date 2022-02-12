//common stuff for unrolling etc.

.syntax unified
.thumb

// columns expected in r0-r3
// Te2 expected in r14
// pointer to expanded key expected in r12

// output columns in r0-r3

// should this replace normal round??
// 16 offset needed if r12 points to ctr+key
.macro CM7_1T_unrolled_enc_round_n round_nr, offset=0
	//start extending from the highest byte and load key/loop later
	uxtb r8, r2, ror #16
	lsr.w r4, r3, #24

	uxtb r9, r3, ror #16
	lsr.w r5, r0, #24

	lsr.w r6, r1, #24
	ldr r4, [r14, r4, lsl #2]

	uxtb r10, r0, ror #16
	ldr r8, [r14, r8, lsl #2]

	lsr.w r7, r2, #24
	ldr r5, [r14, r5, lsl #2]

	uxtb r11, r1, ror #16
	ldr r9, [r14, r9, lsl #2]

	eor r4, r8, r4, ror #24
	ldr r6, [r14, r6, lsl #2]

	eor r5, r9, r5, ror #24
	ldr r10, [r14, r10, lsl #2]

	//cannot eor yet - so try to free up r0
	// r8 -> r4 ror16
	// r9 -> r7 ror8

	uxtb r9, r0, ror #8
	ldr r7, [r14, r7, lsl #2]

	eor r6, r10, r6, ror #24
	ldr r11, [r14, r11, lsl #2]

	uxtb r8, r0 // and
	ldr r9, [r14, r9, lsl #2]

	eor r7, r11, r7, ror #24
	ldr r0, [r12, #\round_nr*16 + \offset + 0]

	//free up r1
	// r10 -> r5 ror16
	// r11 -> r4 ror8

	uxtb r10, r1
	ldr r8, [r14, r8, lsl #2]

	uxtb r11, r1, ror #8
	ldr r1, [r12, #\round_nr*16 + \offset + 4]

	eor r7, r7, r9, ror #8
	ldr r10, [r14, r10, lsl #2]

	eor r4, r4, r8, ror #16
	ldr r11, [r14, r11, lsl #2]

	// now r2
	// r8 -> r6 ror16
	// r9 -> r5 ror8

	uxtb r8, r2
	eor r5, r5, r10, ror #16

	uxtb r9, r2, ror #8
	ldr r2, [r12, #\round_nr*16 + \offset + 8]

	eor r4, r4, r11, ror #8
	ldr r8, [r14, r8, lsl #2]

	// r3
	// r10 -> r7 ror16
	// r11 -> r6 ror8

	uxtb r10, r3
	ldr r9, [r14, r9, lsl #2]

	uxtb r11, r3, ror #8
	ldr r3, [r12, #\round_nr*16 + \offset + 12]

	eor r6, r6, r8, ror #16
	ldr r10, [r14, r10, lsl #2]

	eor r5, r5, r9, ror #8
	ldr r11, [r14, r11, lsl #2]

	eor r7, r7, r10, ror #16
	eor.w r0, r4

	eor r6, r6, r11, ror #8
	eor.w r1, r5

	eor.w r2, r6
	eor.w r3, r7
.endm

.macro CM7_1T_unrolled_enc_round
	//start extending from the highest byte and load key/loop later
	uxtb r8, r2, ror #16
	lsr.w r4, r3, #24

	uxtb r9, r3, ror #16
	lsr.w r5, r0, #24

	lsr.w r6, r1, #24
	ldr r4, [r14, r4, lsl #2]

	uxtb r10, r0, ror #16
	ldr r8, [r14, r8, lsl #2]

	lsr.w r7, r2, #24
	ldr r5, [r14, r5, lsl #2]

	uxtb r11, r1, ror #16
	ldr r9, [r14, r9, lsl #2]

	eor r4, r8, r4, ror #24
	ldr r6, [r14, r6, lsl #2]

	eor r5, r9, r5, ror #24
	ldr r10, [r14, r10, lsl #2]

	//cannot eor yet - so try to free up r0
	// r8 -> r4 ror16
	// r9 -> r7 ror8

	uxtb r9, r0, ror #8
	ldr r7, [r14, r7, lsl #2]

	eor r6, r10, r6, ror #24
	ldr r11, [r14, r11, lsl #2]

	uxtb r8, r0 // and
	ldr r9, [r14, r9, lsl #2]

	eor r7, r11, r7, ror #24
	ldr r0, [r12], #4

	//free up r1
	// r10 -> r5 ror16
	// r11 -> r4 ror8

	uxtb r10, r1
	ldr r8, [r14, r8, lsl #2]

	uxtb r11, r1, ror #8
	ldr r1, [r12], #4

	eor r7, r7, r9, ror #8
	ldr r10, [r14, r10, lsl #2]

	eor r4, r4, r8, ror #16
	ldr r11, [r14, r11, lsl #2]

	// now r2
	// r8 -> r6 ror16
	// r9 -> r5 ror8

	uxtb r8, r2
	eor r5, r5, r10, ror #16

	uxtb r9, r2, ror #8
	ldr r2, [r12], #4

	eor r4, r4, r11, ror #8
	ldr r8, [r14, r8, lsl #2]

	// r3
	// r10 -> r7 ror16
	// r11 -> r6 ror8

	uxtb r10, r3
	ldr r9, [r14, r9, lsl #2]

	uxtb r11, r3, ror #8
	ldr r3, [r12], #4

	eor r6, r6, r8, ror #16
	ldr r10, [r14, r10, lsl #2]

	eor r5, r5, r9, ror #8
	ldr r11, [r14, r11, lsl #2]

	eor r7, r7, r10, ror #16
	eor.w r0, r4

	eor r6, r6, r11, ror #8
	eor.w r1, r5

	eor.w r2, r6
	eor.w r3, r7
.endm

.macro CM7_1T_unrolled_dec_round
	uxtb r8, r2, ror #16
	lsr.w r4, r1, #24

	uxtb r9, r3, ror #16
	lsr.w r5, r2, #24

	lsr.w r6, r3, #24
	ldr r4, [r14, r4, lsl #2]

	uxtb r10, r0, ror #16
	ldr r8, [r14, r8, lsl #2]

	lsr.w r7, r0, #24
	ldr r5, [r14, r5, lsl #2]

	uxtb r11, r1, ror #16
	ldr r9, [r14, r9, lsl #2]

	eor r4, r8, r4, ror #24
	ldr r6, [r14, r6, lsl #2]

	eor r5, r9, r5, ror #24
	ldr r10, [r14, r10, lsl #2]

	//cannot eor yet - so try to free up r0
	// r8 -> r4 ror16
	// r9 -> r5 ror8

	uxtb r9, r0, ror #8
	ldr r7, [r14, r7, lsl #2]

	eor r6, r10, r6, ror #24
	ldr r11, [r14, r11, lsl #2]

	uxtb r8, r0
	ldr r9, [r14, r9, lsl #2]

	eor r7, r11, r7, ror #24
	ldr r0, [r12, #-16]!

	//free up r1
	// r10 -> r5 ror16
	// r11 -> r6 ror8

	uxtb r10, r1
	ldr r8, [r14, r8, lsl #2]

	uxtb r11, r1, ror #8
	ldr r1, [r12, #4]

	eor r5, r5, r9, ror #8
	ldr r10, [r14, r10, lsl #2]

	eor r4, r4, r8, ror #16
	ldr r11, [r14, r11, lsl #2]

	// now r2
	// r8 -> r6 ror16
	// r9 -> r7 ror8

	uxtb r8, r2
	eor r5, r5, r10, ror #16

	uxtb r9, r2, ror #8
	ldr r2, [r12, #8]

	eor r6, r6, r11, ror #8
	ldr r8, [r14, r8, lsl #2]

	// r3
	// r10 -> r7 ror16
	// r11 -> r0 ror8

	uxtb r10, r3
	ldr r9, [r14, r9, lsl #2]

	uxtb r11, r3, ror #8
	ldr r3, [r12, #12]

	eor r6, r6, r8, ror #16
	ldr r10, [r14, r10, lsl #2]

	eor r7, r7, r9, ror #8
	ldr r11, [r14, r11, lsl #2]

	eor r7, r7, r10, ror #16
	eor.w r0, r4

	eor r0, r0, r11, ror #8
	eor.w r1, r5

	eor.w r2, r6
	eor.w r3, r7
.endm
