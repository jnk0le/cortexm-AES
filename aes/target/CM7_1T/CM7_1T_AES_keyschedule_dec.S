// performs perform equivalent inverse cipher transformation on expanded encryption key
// decryprion will be done backwards to avoid extra stacking or redundant code

.syntax unified
.thumb
.text
//.section .itcm.text, "x"

.align 3
// void CM7_1T_AES_keyschedule_dec(uint8_t* rk, size_t rounds) {
.global CM7_1T_AES_keyschedule_dec
.type   CM7_1T_AES_keyschedule_dec,%function
CM7_1T_AES_keyschedule_dec:
	push {r4-r11, lr}

	//first and last block are ommited
	add r11, r0, #16
	add r0, r0, r1, lsl #4 //rk_end-16 = rk + rounds * 16

	movw r14, #:lower16:AES_Te2
	movt r14, #:upper16:AES_Te2
	movw r12, #:lower16:AES_Td2
	movt r12, #:upper16:AES_Td2

	//11 regs available for processing
	//Td[sbox[]] - 3+1(+2) regs, cannot be dual issued with itself or other block
	//dsp invMixColums - 5+1 regs + few more insns, cannot be dual issued with itself
	// r2 = S{1}
	// r5 = S{2}
	// r6 = S{4}
	// r7 = S{8}

	// r9 - S{9} = S{8} ^ S{1}
	// r4 - S{b} = S{9} ^ S{2}
	// r10 - S{d} = S{9} ^ S{4}
	// r7 - S{e} = S{8} ^ S{4} ^ S{2}

	// r2 = s0{e}^s1{b}^s2{d}^s3{9} | s1{e}^s2{b}^s3{d}^s0{9} | s2{e}^s3{b}^s0{d}^s1{9} | s3{e}^s0{b}^s1{d}^s2{9}

	//expand 2 columns in parallel to avoid stalls
	// expand backwards to allow early comparison
1:	ldrd r1,r2, [r0, #-8]! // 8+4 alignment required here // if uxtb and lsrs are both .w, then 8+0 is required // otherwise cycle lost per iteration

	uxtb r3, r1
	uadd8 r5, r2, r2 // quad lsl #1

	uxtb r8, r1, ror #8
	eor r10, r5, #0x1b1b1b1b

	lsrs r4, r1, #24
	sel r5, r10, r5 // if uadd carried then take reduced byte

	uxtb r1, r1, ror #16
	uadd8 r6, r5, r5 // quad lsl #1

	ldrb r3, [r14, r3, lsl #2] //load sbox from Te2
	eor r10, r6, #0x1b1b1b1b

	ldrb r8, [r14, r8, lsl #2] //load sbox from Te2
	sel r6, r10, r6 // if uadd carried then take reduced byte

	ldrb r1, [r14, r1, lsl #2] //load sbox from Te2
	uadd8 r7, r6, r6 // quad lsl #1

	ldrb r4, [r14, r4, lsl #2] //load sbox from Te2
	eor r10, r7, #0x1b1b1b1b

	ldr r3, [r12, r3, lsl #2]
	sel r7, r10, r7 // if uadd carried then take reduced byte

	ldr r8, [r12, r8, lsl #2]
	eor r9, r7, r2

	ldr r1, [r12, r1, lsl #2]
	eor r2, r9, r5

	ldr r4, [r12, r4, lsl #2]
	eor r10, r9, r6

	eor r1, r1, r3, ror #16
	eors r7, r6

	eor r1, r1, r8, ror #8
	eors r7, r5

	eor r1, r1, r4, ror #24
	eor r7, r7, r10, ror #16

	cmp r11, r0 // compare early
	eor r7, r7, r9, ror #24

	str r1, [r0]
	eor r2, r7, r2, ror #8

	str r2, [r0, #4]
	bne 1b

	pop {r4-r11, pc}





