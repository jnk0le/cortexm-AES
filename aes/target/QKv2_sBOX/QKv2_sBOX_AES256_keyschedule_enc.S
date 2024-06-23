/*!
 * \file QKv2_sBOX_AES256_keyschedule_enc.S
 * \brief
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only
#if __riscv && (__riscv_xlen == 32)

// 7 rounds of rcon can be computed as left shift only

#include "aes/target/QKv2_sBOX/QKv2_common.inc"

.text

.balign 4
// void QKv2_sBOX_AES256_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global QKv2_sBOX_AES256_keyschedule_enc
.type   QKv2_sBOX_AES256_keyschedule_enc,%function
QKv2_sBOX_AES256_keyschedule_enc:
	c.addi sp, -12
	c.swsp s0, 0(sp)
	c.swsp s1, 4(sp)
	c.swsp ra, 8(sp)

	// a0 - rk
	// a1 - key

	lui ra, %hi(AES_sbox)
	addi ra, ra, %lo(AES_sbox)

	// load key
	c.lw s1, 0(a1)
	c.lw a2, 8(a1)
	c.lw a3, 12(a1)
	c.lw a4, 16(a1)
	c.lw a5, 20(a1)
	lw t1, 24(a1)
	lw t2, 28(a1)
	c.lw a1, 4(a1) // a1 as last

	//store rk
	c.sw s1, 0(a0)
	c.sw a1, 4(a0)
	c.sw a2, 8(a0)
	c.sw a3, 12(a0)
	//2nd part skewed into loop

	c.li t0, 1

	// register allocation
	// s0 - tmp
	// s1 - k0
	// a0 - rk
	// a1 - k1
	// a2 - k2
	// a3 - k3
	// a4 - k4
	// a5 - k5
	// t0 - rcon
	// t1 - k6
	// t2 - k7
	// ra - sbox
.balign 4
1:
	// store rk from prev round
	c.sw a4, 16(a0)
	c.sw a5, 20(a0)
	sw t1, 24(a0)
	sw t2, 28(a0)

	srli s0, t2, 8
	zext.b s0, s0
	c.add s0, ra
	xw_.c.lbu s0, s0
	c.xor s1, s0

	srli s0, t2, 16
	zext.b s0, s0
	c.add s0, ra
	xw_.c.lbu s0, s0
	c.slli s0, 8
	c.xor s1, s0

	srli s0, t2, 24
	c.add s0, ra
	xw_.c.lbu s0, s0
	c.slli s0, 16
	c.xor s1, s0

	zext.b s0, t2
	c.add s0, ra
	xw_.c.lbu s0, s0
	c.slli s0, 24
	c.xor s1, s0

	xor s1, s1, t0 // apply rcon
	c.xor a1, s1
	c.xor a2, a1
	c.xor a3, a2

	// rk has not been incremented yet
	c.sw s1, 32(a0)
	c.sw a1, 36(a0)
	c.sw a2, 40(a0)
	c.sw a3, 44(a0)

	slli s0, t0, 26 // shift out rcon if 0x40 reached
	c.beqz s0, 2f // final condition reached

	//g transform // just sbox
	zext.b s0, a3
	c.add s0, ra
	xw_.c.lbu s0, s0
	c.xor a4, s0

	srli s0, a3, 8
	zext.b s0, s0
	c.add s0, ra
	xw_.c.lbu s0, s0
	c.slli s0, 8
	c.xor a4, s0

	srli s0, a3, 16
	zext.b s0, s0
	c.add s0, ra
	xw_.c.lbu s0, s0
	c.slli s0, 16
	c.xor a4, s0

	srli s0, a3, 24
	c.add s0, ra
	xw_.c.lbu s0, s0
	c.slli s0, 24
	c.xor a4, s0

	c.xor a5, a4
	xor t1, t1, a5
	xor t2, t2, t1

	c.slli t0, 1 // next rcon
	addi a0, a0, 32 // incr rk
	c.j 1b

2:
	c.lwsp ra, 8(sp)
	c.lwsp s1, 4(sp)
	c.lwsp s0, 0(sp)
	c.addi sp, 12
	ret

#endif
