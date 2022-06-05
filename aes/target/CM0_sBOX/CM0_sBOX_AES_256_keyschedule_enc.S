/*!
 * \file CM0_sBOX_AES_256_keyschedule_enc.S
 * \brief
 *
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date 29 oct 2021
 */

// 7 rounds of rcon can be computed as left shift only

.syntax unified
.thumb
.text

.align 2
// void CM0_sBOX_AES_256_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM0_sBOX_AES_256_keyschedule_enc
.type   CM0_sBOX_AES_256_keyschedule_enc,%function
CM0_sBOX_AES_256_keyschedule_enc:
	push {r4-r7, lr}
	mov r4, r8
	mov r5, r9
	mov r6, r10
	push {r4-r6}

	ldmia r1!, {r2-r5} // load key
	stmia r0!, {r2-r5} // just copy a key

	//swap out middle part due to pressure
	//r2 r8 r9 r5 // part1
	//r3 r4 r6 r7 // part2

	mov r8, r3
	mov r9, r4

	ldmia r1!, {r3,r4,r6,r7} // load key
	stmia r0!, {r3,r4,r6,r7} // just copy a key

	movs r1, #1
	mov r12, r1 // save rcon

	mov r14, r0 // save rk

	ldr r0, =AES_sbox

1:	// r8 - r3 part1
	// r9 - r4 part1
	// r10 -
	// r12 - rcon
	// r14 - rk

	// unswap to process first part
	mov r10, r3
	mov r3, r8

	mov r8, r4
	mov r4, r9

	lsrs r1, r7, #8
	uxtb r1, r1
	ldrb r1, [r0, r1]
	eors r2, r1

	lsrs r1, r7, #16
	uxtb r1, r1
	ldrb r1, [r0, r1]
	lsls r1, #8
	eors r2, r1

	lsrs r1, r7, #24
	ldrb r1, [r0, r1]
	lsls r1, #16
	eors r2, r1

	uxtb r1, r7
	ldrb r1, [r0, r1]
	lsls r1, #24
	eors r2, r1

	mov r1, r12 // get rcon
	eors r2, r1 // apply rcon

	eors r3, r2
	eors r4, r3
	eors r5, r4

	add r12, r12 // left shift rcon
	cmp r1, #0x40

	mov r1, r14 // get rk

	stmia r1!, {r2-r5} // first half
	beq 2f // break halfway

	mov r14, r1 // put rk back

	// r8 - r4 part2
	// r9 -
	// r10 - r3 part2

	// swap to process second part
	mov r9, r4
	mov r4, r8

	mov r8, r3
	mov r3, r10

	//g transform // just sbox
	uxtb r1, r5
	ldrb r1, [r0, r1]
	eors r3, r1

	lsrs r1, r5, #8
	uxtb r1, r1
	ldrb r1, [r0, r1]
	lsls r1, #8
	eors r3, r1

	lsrs r1, r5, #16
	uxtb r1, r1
	ldrb r1, [r0, r1]
	lsls r1, #16
	eors r3, r1

	lsrs r1, r5, #24
	ldrb r1, [r0, r1]
	lsls r1, #24
	eors r3, r1

	eors r4, r3
	eors r6, r4
	eors r7, r6

	mov r1, r14 // get rk
	stmia r1!, {r3,r4,r6,r7}
	mov r14, r1 // put rk back
	b 1b

2:	pop {r4-r6}
	mov r8, r4
	mov r9, r5
	mov r10, r6
	pop {r4-r7, pc}
