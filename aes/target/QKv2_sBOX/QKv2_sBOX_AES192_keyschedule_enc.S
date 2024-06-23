/*!
 * \file QKv2_sBOX_AES192_keyschedule_enc.S
 * \brief
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only
#if __riscv && (__riscv_xlen == 32)

// 8 rounds of rcon can be computed as left shift only

#include "aes/target/QKv2_sBOX/QKv2_common.inc"

.text

.balign 4
// void QKv2_sBOX_AES192_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global QKv2_sBOX_AES192_keyschedule_enc
.type   QKv2_sBOX_AES192_keyschedule_enc,%function
QKv2_sBOX_AES192_keyschedule_enc:
	c.addi sp, -8
	c.swsp s0, 0(sp)
	c.swsp s1, 4(sp)

	// a0 - rk
	// a1 - key

	// load key
	c.lw s1, 0(a1)

	lui t2, %hi(AES_sbox)
	addi t2, t2, %lo(AES_sbox)

	c.lw a2, 8(a1)
	c.lw a3, 12(a1)

	li t1, 0x80

	c.lw a4, 16(a1)
	c.lw a5, 20(a1)

	c.li t0, 1
	c.lw a1, 4(a1) // a1 as last

	// rk store is skewed into the round

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
	// t1 - 0x80 // final condition
	// t2 - sbox

.balign 4
1:
	c.sw s1, 0(a0) // store rk from prev round
	c.sw a1, 4(a0)

	srli s0, a5, 8
	c.sw a2, 8(a0) // store rk from prev round
	c.sw a3, 12(a0)
	zext.b s0, s0
	c.add s0, t2
	xw_.c.lbu s0, s0
	c.xor s1, s0

	srli s0, a5, 16
	c.sw a4, 16(a0) // store rk from prev round
	c.sw a5, 20(a0)
	zext.b s0, s0
	c.add s0, t2
	xw_.c.lbu s0, s0
	c.slli s0, 8
	c.xor s1, s0

	srli s0, a5, 24
	c.add s0, t2
	xw_.c.lbu s0, s0
	c.slli s0, 16
	c.xor s1, s0

	zext.b s0, a5
	c.add s0, t2
	xw_.c.lbu s0, s0
	c.slli s0, 24
	c.xor s1, s0

	xor s1, s1, t0 // apply rcon
	c.xor a1, s1
	c.xor a2, a1
	c.xor a3, a2
	c.xor a4, a3
	c.xor a5, a4

	beq t0, t1, 2f // final condition

	c.addi a0, 24 // next rk
	c.slli t0, 1 // next rcon
	c.j 1b

2:
	// store remaining rk
	// rk was not incremented in final round
	c.sw s1, 24(a0)
	c.sw a1, 28(a0)
	c.sw a2, 32(a0)
	c.sw a3, 36(a0)
	c.sw a4, 40(a0)
	c.sw a5, 44(a0)

	c.lwsp s1, 4(sp)
	c.lwsp s0, 0(sp)
	c.addi sp, 8
	ret

#endif
