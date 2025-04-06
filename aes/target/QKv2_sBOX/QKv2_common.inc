/*!
 * \file QKv2_common.inc
 * \brief common sequences and macros for qkv2
 *
 * implements some of the xw instructions without requirement of proprietary GCC
 * uses "xw_" prefix as to not collide with eventualy upstreamable names with more normal syntax
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

.macro xw_.c.lbu rd, rs, uimm=0
	// rotate uimm5 right by 1 to match encoding
	.insn cl C0, 0b001, \rd, ((\uimm>>1) | ((\uimm & 1) << 4))(\rs)
.endm
