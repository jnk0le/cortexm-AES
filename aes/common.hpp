/*!
 * \file common.hpp
 * \brief
 *
 * \author Jan Oleksiewicz <jnk0le@hotmail.com>
 * \license SPDX-License-Identifier: MIT
 */

#ifndef AES_COMMON_HPP
#define AES_COMMON_HPP

#if __cplusplus >= 202302L
	#include <bit>
#endif

#if __cplusplus >= 202302L
	static_assert(std::endian::native == std::endian::little, "only little endian archs are supported");
#endif


namespace aes {
namespace common {

#if __cplusplus < 202302L
	using std::byteswap;
#else
	constexpr uint32_t byteswap(uint32_t value) {
		return __builtin_bswap32(value);
	}
	constexpr uint64_t byteswap(uint64_t value) {
		return __builtin_bswap64(value);
	}
#endif

}
}

#endif
