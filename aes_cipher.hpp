/*!
 * \file aes_cipher.hpp
 * \version 1.0.0
 * \brief basic ECB cipher context class
 *
 * \warning Do not use ECB mode for more than 16 bytes of plaintext data.
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date Jun 2018
 */

#ifndef AES_HPP
#define AES_HPP

#include <stdint.h>

#include "target/AES_CM34.h"

namespace aes
{
	// cannot partially specialize single member functions
	// CRTP might be a better way to avoid highly redundant code

	/*enum class Target
	{
		GENERIC,
		CM34_1T
	};*/

template<size_t key_length> //, Target impl = Target::CM34_1T>
	class CipherContext
	{
	public:
		CipherContext() {}
		//copy constructor ??
		~CipherContext() {}

		void setEncKey(const uint8_t* key);

		void setDecKey(const uint8_t* key);
		void setDecKey(void);

		void encrypt(uint8_t* data) const {
			encrypt(data, data);
		}
		void encrypt(const uint8_t* data_in, uint8_t* data_out) const;

		void decrypt(uint8_t* data) const {
			decrypt(data, data);
		}
		void decrypt(const uint8_t* data_in, uint8_t* data_out) const;

	private:
		static constexpr size_t key_rounds = (key_length == 128) ? 10 : ((key_length == 192) ? 12 : 14);

		uint8_t round_key[(key_rounds+1)*16];

		static_assert(key_length == 128 || key_length == 192 || key_length == 256,
				"non standard key lengths are not supported");
	};

template<size_t key_length>
	void CipherContext<key_length>::setEncKey(const uint8_t* key)
	{
		switch(key_length)
		{
		case 128:
			AES_128_keyschedule_enc(this->round_key, key);
			break;
		case 192:
			AES_192_keyschedule_enc(this->round_key, key);
			break;
		case 256:
			AES_256_keyschedule_enc(this->round_key, key);
			break;
		}
	}

template<size_t key_length>
	void CipherContext<key_length>::setDecKey(const uint8_t* key)
	{
		this->setEncKey(key);
		AES_keyschedule_dec(this->round_key, this->key_rounds);
	}

template<size_t key_length>
	void CipherContext<key_length>::setDecKey(void)
	{
		AES_keyschedule_dec(this->round_key, this->key_rounds);
	}

template<size_t key_length>
	void CipherContext<key_length>::encrypt(const uint8_t* data_in, uint8_t* data_out) const
	{
		AES_encrypt(this->round_key, data_in, data_out, this->key_rounds);
	}

template<size_t key_length>
	void CipherContext<key_length>::decrypt(const uint8_t* data_in, uint8_t* data_out) const
	{
		AES_decrypt(this->round_key, data_in, data_out, this->key_rounds);
	}
}

#endif // AES_HPP
