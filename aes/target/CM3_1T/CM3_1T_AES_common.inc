//common stuff for unrolling etc.

.syntax unified
.thumb

//columns expected in r4-r7
//Te2 expected in r14
//pointer to expanded key expected in r12

.macro CM3_1T_unrolled_enc_round_n round_nr, offset=0
	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	ldr r8, [r12, #\round_nr*16 + \offset + 0]
	ldr r9, [r12, #\round_nr*16 + \offset + 4]
	ldr r10, [r12, #\round_nr*16 + \offset + 8]
	ldr r11, [r12, #\round_nr*16 + \offset + 12]
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
.endm


.macro CM3_1T_unrolled_dec_round



.endm
