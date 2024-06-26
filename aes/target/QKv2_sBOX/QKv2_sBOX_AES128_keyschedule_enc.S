/*!
 * \file QKv2_sBOX_AES128_keyschedule_enc.S
 * \brief
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

// compile for compatible targets only
#if __riscv && (__riscv_xlen == 32)

// 10 rounds of rcon can be computed as left shift + conditional reload of rcon to 0x1b after 0x80
// it can also serve as loop counter to reduce register pressure


#include "aes/target/QKv2_sBOX/QKv2_common.inc"

.text

.balign 4
// void QKv2_sBOX_AES128_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global QKv2_sBOX_AES128_keyschedule_enc
.type   QKv2_sBOX_AES128_keyschedule_enc,%function
QKv2_sBOX_AES128_keyschedule_enc:
	c.addi sp, -4
	c.swsp s0, 0(sp)

	// a0 - rk
	// a1 - key

	li t1, 0x36

	// load key
	c.lw a2, 0(a1)
	c.lw a3, 4(a1)

	li t2, 0x100

	c.lw a4, 8(a1)
	c.lw a5, 12(a1)

	lui a1, %hi(AES_sbox)
	addi a1, a1, %lo(AES_sbox)

	c.sw a2, 0(a0) // store rk, rest is skewed into the round
	c.li t0, 1

	// register allocation
	// s0 - tmp
	// s1 -
	// a0 - rk
	// a1 - sbox
	// a2 - k0
	// a3 - k1
	// a4 - k2
	// a5 - k3

	// t0 - rcon // better here than spilling
	// t1 - 0x36 // final condition
	// t2 - 0x100 // rcon reload condition
.balign 4
1:
	c.sw a3, 4(a0) // store rk from prev round
	c.sw a4, 8(a0)

	srli s0, a5, 8
	zext.b s0, s0
	c.add s0, a1
	xw_.c.lbu s0, s0
	c.xor a2, s0

	c.sw a5, 12(a0) // store rk from prev round

	srli s0, a5, 16
	zext.b s0, s0
	c.add s0, a1
	xw_.c.lbu s0, s0
	c.slli s0, 8
	c.xor a2, s0

	srli s0, a5, 24
	c.add s0, a1
	xw_.c.lbu s0, s0
	c.slli s0, 16
	c.xor a2, s0

	zext.b s0, a5
	c.add s0, a1
	xw_.c.lbu s0, s0
	c.slli s0, 24
	c.xor a2, s0

	xor a2, a2, t0 // apply rcon
	c.xor a3, a2
	c.xor a4, a3
	c.xor a5, a4

	c.sw a2, 16(a0) // rk was not incremented yet

	beq t0, t1, 2f // final condition

	c.addi a0, 16 // next rk
	c.slli t0, 1 // next rcon
	bne t0, t2, 1b // rcon is not secret

	c.li t0, 0x1b
	c.j 1b

2:	// store remaining rk
	// rk was not incremented in final round
	c.sw a3, 20(a0)
	c.sw a4, 24(a0)
	c.sw a5, 28(a0)

	c.lwsp s0, 0(sp)
	c.addi sp, 4
	ret

#endif
