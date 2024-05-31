/*!
 * \file QKv2_sBOX_AES_decrypt.S
 * \brief
 *
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */


#if __riscv && (__riscv_xlen == 32)

.text

.balign 4
// void QKv2_sBOX_AES_decrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global QKv2_sBOX_AES_decrypt
.type   QKv2_sBOX_AES_decrypt,%function
QKv2_sBOX_AES_decrypt:

	ret

#endif
