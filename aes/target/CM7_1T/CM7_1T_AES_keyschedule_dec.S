// in place expansion of round key for decryption
// do it backwards to avoid stacking or redundant code
// requires already expanded encryption key

// LUT loads are splitted to avoid data dependent issuing capability from even/odd DTCM words

.syntax unified
.thumb
.text
//.section .itcm.text, "x"

.align 3
// void CM7_1T_AES_keyschedule_dec(uint8_t* rk, size_t rounds) {
.global CM7_1T_AES_keyschedule_dec
.type   CM7_1T_AES_keyschedule_dec,%function
CM7_1T_AES_keyschedule_dec:
	push {r4-r9, lr}

	//first and last block is ommited
	//rk_end-16 = rk + rounds * 16
	add r1, r0, r1, lsl #4
	add r0, #16 //align following code to 4 bytes

	movw r14, #:lower16:AES_Te2
	movt r14, #:upper16:AES_Te2
	movw r12, #:lower16:AES_Td2
	//movt is optimized into wasted cycles

1:	ldmdb r1!, {r2-r5}

	uxtb r6, r2, ror #8
	uxtb r7, r2, ror #16
	//cannot dual issue when load offset is blocked by uxtb

	uxtb r8, r2, ror #24
	ldrb r6, [r14, r6, lsl #2] //load sbox from Te0

	uxtb r9, r2
	ldrb r7, [r14, r7, lsl #2] //load sbox from Te0

	movt r12, #:upper16:AES_Td2
	ldrb r8, [r14, r8, lsl #2] //load sbox from Te0

	nop
	ldrb r9, [r14, r9, lsl #2] //load sbox from Te0
	nop
	ldr r6, [r12, r6, lsl #2]
	nop
	ldr r2, [r12, r7, lsl #2]
	nop
	ldr r8, [r12, r8, lsl #2]

	uxtb r7, r3, ror #16
	ldr r9, [r12, r9, lsl #2]

	eor r2, r2, r8, ror #24
	uxtb r8, r3, ror #24

	eor r2, r2, r9, ror #16
	uxtb r9, r3

	eor r2, r2, r6, ror #8
	uxtb r6, r3, ror #8

	nop
	ldrb r6, [r14, r6, lsl #2] //load sbox from Te0
	nop
	ldrb r7, [r14, r7, lsl #2] //load sbox from Te0
	nop
	ldrb r8, [r14, r8, lsl #2] //load sbox from Te0
	nop
	ldrb r9, [r14, r9, lsl #2] //load sbox from Te0
	nop
	ldr r6, [r12, r6, lsl #2]
	nop
	ldr r3, [r12, r7, lsl #2]
	nop
	ldr r8, [r12, r8, lsl #2]

	uxtb r7, r4, ror #16
	ldr r9, [r12, r9, lsl #2]

	eor r3, r3, r8, ror #24
	uxtb r8, r4, ror #24

	eor r3, r3, r9, ror #16
	uxtb r9, r4

	eor r3, r3, r6, ror #8
	uxtb r6, r4, ror #8

	strd r2,r3, [r1] // write rk back

	nop
	ldrb r6, [r14, r6, lsl #2] //load sbox from Te0
	nop
	ldrb r7, [r14, r7, lsl #2] //load sbox from Te0
	nop
	ldrb r8, [r14, r8, lsl #2] //load sbox from Te0
	nop
	ldrb r9, [r14, r9, lsl #2] //load sbox from Te0
	nop
	ldr r6, [r12, r6, lsl #2]
	nop
	ldr r4, [r12, r7, lsl #2]
	nop
	ldr r8, [r12, r8, lsl #2]

	uxtb r7, r5, ror #16
	ldr r9, [r12, r9, lsl #2]

	eor r4, r4, r8, ror #24
	uxtb r8, r5, ror #24

	eor r4, r4, r9, ror #16
	uxtb r9, r5

	eor r4, r4, r6, ror #8
	uxtb r6, r5, ror #8

	nop
	ldrb r6, [r14, r6, lsl #2] //load sbox from Te0
	nop
	ldrb r7, [r14, r7, lsl #2] //load sbox from Te0
	nop
	ldrb r8, [r14, r8, lsl #2] //load sbox from Te0
	nop
	ldrb r9, [r14, r9, lsl #2] //load sbox from Te0
	nop
	ldr r6, [r12, r6, lsl #2]
	nop
	ldr r5, [r12, r7, lsl #2]
	nop
	ldr r8, [r12, r8, lsl #2]

	ldr r9, [r12, r9, lsl #2]
	eor r5, r5, r8, ror #24

	cmp r1, r0 // will use flags later
	eor r5, r5, r9, ror #16

	eor r5, r5, r6, ror #8

	strd r4,r5, [r1, #8] // write rk back

	//nop ?
	bne 1b

	pop {r4-r9, pc}
