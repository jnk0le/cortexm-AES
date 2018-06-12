// uses backward expanded round key

.syntax unified
.thumb
.text

.align 2
// void AES_decrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global AES_decrypt
.type   AES_decrypt,%function
AES_decrypt:
	adds r0, #16 //to compare against before final round
	push {r0, r2, r4-r11, lr} //stack rk+16, out

	movw r14, #:lower16:AES_Td0
	movt r14, #:upper16:AES_Td0

	//rk_end = rk+16 + rounds * 16
	add r12, r0, r3, lsl #4

	//load input
	ldmia r1!, {r4-r7}

	//load initial round key
	ldmdb r12!, {r0-r3}

	//initial addroundkey
	eors r4, r0
	eors r5, r1
	eors r6, r2
	eors r7, r3

1:	ldmdb r12!, {r8-r11}

	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	eor r8, r8, r0, ror #16
	eor r9, r9, r1, ror #16
	eor r10, r10, r2, ror #16
	eor r11, r11, r3, ror #16

	uxtb r0, r7, ror #8
	uxtb r1, r4, ror #8
	uxtb r2, r5, ror #8
	uxtb r3, r6, ror #8
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
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	eor r8, r0
	eor r9, r1
	eor r10, r2
	eor r11, r3

	uxtb r0, r5, ror #24
	uxtb r1, r6, ror #24
	uxtb r2, r7, ror #24
	uxtb r3, r4, ror #24
	ldr r0, [r14, r0, lsl #2]
	ldr r1, [r14, r1, lsl #2]
	ldr r2, [r14, r2, lsl #2]
	ldr r3, [r14, r3, lsl #2]
	eor r4, r8, r0, ror #24
	eor r5, r9, r1, ror #24
	eor r6, r10, r2, ror #24
	eor r7, r11, r3, ror #24

	ldr r0, [sp]
	cmp r0, r12

	bne.w 1b //align following code to 4 bytes

	//do we really need inv_sbox?
	movw r14, #:lower16:AES_inv_sbox
	movt r14, #:upper16:AES_inv_sbox

	//final round
	ldmdb r12, {r8-r11}

	uxtb r0, r4
	uxtb r1, r5
	uxtb r2, r6
	uxtb r3, r7
	ldrb r0, [r14, r0]
	ldrb r1, [r14, r1]
	ldrb r2, [r14, r2]
	ldrb r3, [r14, r3]
	eor r8, r0
	eor r9, r1
	eor r10, r2
	eor r11, r3

	uxtb r0, r7, ror #8
	uxtb r1, r4, ror #8
	uxtb r2, r5, ror #8
	uxtb r3, r6, ror #8
	ldrb r0, [r14, r0]
	ldrb r1, [r14, r1]
	ldrb r2, [r14, r2]
	ldrb r3, [r14, r3]
	eor r8, r8, r0, lsl #8
	eor r9, r9, r1, lsl #8
	eor r10, r10, r2, lsl #8
	eor r11, r11, r3, lsl #8

	uxtb r0, r6, ror #16
	uxtb r1, r7, ror #16
	uxtb r2, r4, ror #16
	uxtb r3, r5, ror #16
	ldrb r0, [r14, r0]
	ldrb r1, [r14, r1]
	ldrb r2, [r14, r2]
	ldrb r3, [r14, r3]
	eor r8, r8, r0, lsl #16
	eor r9, r9, r1, lsl #16
	eor r10, r10, r2, lsl #16
	eor r11, r11, r3, lsl #16

	uxtb r0, r5, ror #24
	uxtb r1, r6, ror #24
	uxtb r2, r7, ror #24
	uxtb r3, r4, ror #24
	ldrb r0, [r14, r0]
	ldrb r1, [r14, r1]
	ldrb r2, [r14, r2]
	ldrb r3, [r14, r3]
	ldr r4, [sp, #4] //load output pointer

	eor r0, r8, r0, lsl #24
	eor r1, r9, r1, lsl #24
	eor r2, r10, r2, lsl #24
	eor r3, r11, r3, lsl #24

	str r0, [r4, #0]
	str r1, [r4, #4]
	str r2, [r4, #8]
	str r3, [r4, #12]

	add sp, #8 //less mem pressure than preindexed load + dummy pop

	pop {r4-r11, pc}
