/*!
 * \file AES_lookup_tables.c
 * \brief lookup tables used in some implementations
 *
 * If something is unused it will not waste memory.
 *
 * Alignment is required to avoid crossing 2 different memory blocks. (minimum AHB granurality for bus slave in cortex-m is 1kB)
 * You might want to create dedicated section in linker script for those,to make sure that the correct memory block is used.
 *
 * To avoid data dependent load time differences, those tables have to be placed in deterministic memory section. (usually TCM/SRAM)
 *
 * `const` specifier cannot be used since it will move tables to flash memory that is not only non-deterministic, but it also
 *  beats the main purpose of using large lookup tables.
 *
 * \todo runtime gen at startup instead of storage
 *
 * \author jnk0le <jnk0le@hotmail.com>
 * \copyright MIT License
 * \date Jun 2018
 */

#include <stdint.h>

/*
	Use section attribute to put tables in a designated deterministic section (.data is used by default)
	I recommend using ".section.XXX" naming to let the compiler do proper GC and reordering.

	section(".AES_TABLES.sbox")
	section(".AES_TABLES.inv_sbox")
	section(".AES_TABLES.Te2")
	section(".AES_TABLES.Td2")

	If .data section is already in DTCM and you just want to make sure it is as explicit as possible

	.data : ALIGN(4) {
		PROVIDE(__data_start__ = .);
		*(.AES_TABLES .AES_TABLES*)
		*(.data .data* .gnu.linkonce.d*)
		PROVIDE(__data_end__ = .);
	} > DTCM AT > FLASH

	If .data section is not placed in deterministic memory block, then you have to create another output section:

	.AES_TABLES : ALIGN(4) {
		PROVIDE(__aes_tables_start__ = .);
		*(.AES_TABLES .AES_TABLES*)
		PROVIDE(__aes_tables_end__ = .);
	} > DTCM AT > FLASH

	PROVIDE(__aes_tables_init_start__ = LOADADDR(.AES_TABLES));

	and initialize it somewhere at startup:

	extern size_t __aes_tables_init_start__;
	extern size_t __aes_tables_start__;
	extern size_t __aes_tables_end__;

	for(int i = 0; i < (&__aes_tables_end__ - &__aes_tables_start__); i++) {
		(&__aes_tables_start__)[i] = (&__aes_tables_init_start__)[i]; // copy by 4 bytes
	}
 */

uint8_t AES_sbox[256] __attribute__((aligned(256), section(".data.AES_sbox"))) =
{
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

uint8_t AES_inv_sbox[256] __attribute__((aligned(256), section(".data.AES_inv_sbox"))) =
{
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

uint32_t AES_Te2[256] __attribute__((aligned(1024), section(".data.AES_Te2"))) =
{
	0x63c6a563, 0x7cf8847c, 0x77ee9977, 0x7bf68d7b,
	0xf2ff0df2, 0x6bd6bd6b, 0x6fdeb16f, 0xc59154c5,
	0x30605030, 0x01020301, 0x67cea967, 0x2b567d2b,
	0xfee719fe, 0xd7b562d7, 0xab4de6ab, 0x76ec9a76,
	0xca8f45ca, 0x821f9d82, 0xc98940c9, 0x7dfa877d,
	0xfaef15fa, 0x59b2eb59, 0x478ec947, 0xf0fb0bf0,
	0xad41ecad, 0xd4b367d4, 0xa25ffda2, 0xaf45eaaf,
	0x9c23bf9c, 0xa453f7a4, 0x72e49672, 0xc09b5bc0,
	0xb775c2b7, 0xfde11cfd, 0x933dae93, 0x264c6a26,
	0x366c5a36, 0x3f7e413f, 0xf7f502f7, 0xcc834fcc,
	0x34685c34, 0xa551f4a5, 0xe5d134e5, 0xf1f908f1,
	0x71e29371, 0xd8ab73d8, 0x31625331, 0x152a3f15,
	0x04080c04, 0xc79552c7, 0x23466523, 0xc39d5ec3,
	0x18302818, 0x9637a196, 0x050a0f05, 0x9a2fb59a,
	0x070e0907, 0x12243612, 0x801b9b80, 0xe2df3de2,
	0xebcd26eb, 0x274e6927, 0xb27fcdb2, 0x75ea9f75,
	0x09121b09, 0x831d9e83, 0x2c58742c, 0x1a342e1a,
	0x1b362d1b, 0x6edcb26e, 0x5ab4ee5a, 0xa05bfba0,
	0x52a4f652, 0x3b764d3b, 0xd6b761d6, 0xb37dceb3,
	0x29527b29, 0xe3dd3ee3, 0x2f5e712f, 0x84139784,
	0x53a6f553, 0xd1b968d1, 0x00000000, 0xedc12ced,
	0x20406020, 0xfce31ffc, 0xb179c8b1, 0x5bb6ed5b,
	0x6ad4be6a, 0xcb8d46cb, 0xbe67d9be, 0x39724b39,
	0x4a94de4a, 0x4c98d44c, 0x58b0e858, 0xcf854acf,
	0xd0bb6bd0, 0xefc52aef, 0xaa4fe5aa, 0xfbed16fb,
	0x4386c543, 0x4d9ad74d, 0x33665533, 0x85119485,
	0x458acf45, 0xf9e910f9, 0x02040602, 0x7ffe817f,
	0x50a0f050, 0x3c78443c, 0x9f25ba9f, 0xa84be3a8,
	0x51a2f351, 0xa35dfea3, 0x4080c040, 0x8f058a8f,
	0x923fad92, 0x9d21bc9d, 0x38704838, 0xf5f104f5,
	0xbc63dfbc, 0xb677c1b6, 0xdaaf75da, 0x21426321,
	0x10203010, 0xffe51aff, 0xf3fd0ef3, 0xd2bf6dd2,
	0xcd814ccd, 0x0c18140c, 0x13263513, 0xecc32fec,
	0x5fbee15f, 0x9735a297, 0x4488cc44, 0x172e3917,
	0xc49357c4, 0xa755f2a7, 0x7efc827e, 0x3d7a473d,
	0x64c8ac64, 0x5dbae75d, 0x19322b19, 0x73e69573,
	0x60c0a060, 0x81199881, 0x4f9ed14f, 0xdca37fdc,
	0x22446622, 0x2a547e2a, 0x903bab90, 0x880b8388,
	0x468cca46, 0xeec729ee, 0xb86bd3b8, 0x14283c14,
	0xdea779de, 0x5ebce25e, 0x0b161d0b, 0xdbad76db,
	0xe0db3be0, 0x32645632, 0x3a744e3a, 0x0a141e0a,
	0x4992db49, 0x060c0a06, 0x24486c24, 0x5cb8e45c,
	0xc29f5dc2, 0xd3bd6ed3, 0xac43efac, 0x62c4a662,
	0x9139a891, 0x9531a495, 0xe4d337e4, 0x79f28b79,
	0xe7d532e7, 0xc88b43c8, 0x376e5937, 0x6ddab76d,
	0x8d018c8d, 0xd5b164d5, 0x4e9cd24e, 0xa949e0a9,
	0x6cd8b46c, 0x56acfa56, 0xf4f307f4, 0xeacf25ea,
	0x65caaf65, 0x7af48e7a, 0xae47e9ae, 0x08101808,
	0xba6fd5ba, 0x78f08878, 0x254a6f25, 0x2e5c722e,
	0x1c38241c, 0xa657f1a6, 0xb473c7b4, 0xc69751c6,
	0xe8cb23e8, 0xdda17cdd, 0x74e89c74, 0x1f3e211f,
	0x4b96dd4b, 0xbd61dcbd, 0x8b0d868b, 0x8a0f858a,
	0x70e09070, 0x3e7c423e, 0xb571c4b5, 0x66ccaa66,
	0x4890d848, 0x03060503, 0xf6f701f6, 0x0e1c120e,
	0x61c2a361, 0x356a5f35, 0x57aef957, 0xb969d0b9,
	0x86179186, 0xc19958c1, 0x1d3a271d, 0x9e27b99e,
	0xe1d938e1, 0xf8eb13f8, 0x982bb398, 0x11223311,
	0x69d2bb69, 0xd9a970d9, 0x8e07898e, 0x9433a794,
	0x9b2db69b, 0x1e3c221e, 0x87159287, 0xe9c920e9,
	0xce8749ce, 0x55aaff55, 0x28507828, 0xdfa57adf,
	0x8c038f8c, 0xa159f8a1, 0x89098089, 0x0d1a170d,
	0xbf65dabf, 0xe6d731e6, 0x4284c642, 0x68d0b868,
	0x4182c341, 0x9929b099, 0x2d5a772d, 0x0f1e110f,
	0xb07bcbb0, 0x54a8fc54, 0xbb6dd6bb, 0x162c3a16,
};

uint32_t AES_Td2[256] __attribute__((aligned(1024), section(".data.AES_Td2"))) =
{
	0xf45150a7, 0x417e5365, 0x171ac3a4, 0x273a965e,
	0xab3bcb6b, 0x9d1ff145, 0xfaacab58, 0xe34b9303,
	0x302055fa, 0x76adf66d, 0xcc889176, 0x02f5254c,
	0xe54ffcd7, 0x2ac5d7cb, 0x35268044, 0x62b58fa3,
	0xb1de495a, 0xba25671b, 0xea45980e, 0xfe5de1c0,
	0x2fc30275, 0x4c8112f0, 0x468da397, 0xd36bc6f9,
	0x8f03e75f, 0x9215959c, 0x6dbfeb7a, 0x5295da59,
	0xbed42d83, 0x7458d321, 0xe0492969, 0xc98e44c8,
	0xc2756a89, 0x8ef47879, 0x58996b3e, 0xb927dd71,
	0xe1beb64f, 0x88f017ad, 0x20c966ac, 0xce7db43a,
	0xdf63184a, 0x1ae58231, 0x51976033, 0x5362457f,
	0x64b1e077, 0x6bbb84ae, 0x81fe1ca0, 0x08f9942b,
	0x48705868, 0x458f19fd, 0xde94876c, 0x7b52b7f8,
	0x73ab23d3, 0x4b72e202, 0x1fe3578f, 0x55662aab,
	0xebb20728, 0xb52f03c2, 0xc5869a7b, 0x37d3a508,
	0x2830f287, 0xbf23b2a5, 0x0302ba6a, 0x16ed5c82,
	0xcf8a2b1c, 0x79a792b4, 0x07f3f0f2, 0x694ea1e2,
	0xda65cdf4, 0x0506d5be, 0x34d11f62, 0xa6c48afe,
	0x2e349d53, 0xf3a2a055, 0x8a0532e1, 0xf6a475eb,
	0x830b39ec, 0x6040aaef, 0x715e069f, 0x6ebd5110,
	0x213ef98a, 0xdd963d06, 0x3eddae05, 0xe64d46bd,
	0x5491b58d, 0xc471055d, 0x06046fd4, 0x5060ff15,
	0x981924fb, 0xbdd697e9, 0x4089cc43, 0xd967779e,
	0xe8b0bd42, 0x8907888b, 0x19e7385b, 0xc879dbee,
	0x7ca1470a, 0x427ce90f, 0x84f8c91e, 0x00000000,
	0x80098386, 0x2b3248ed, 0x111eac70, 0x5a6c4e72,
	0x0efdfbff, 0x850f5638, 0xae3d1ed5, 0x2d362739,
	0x0f0a64d9, 0x5c6821a6, 0x5b9bd154, 0x36243a2e,
	0x0a0cb167, 0x57930fe7, 0xeeb4d296, 0x9b1b9e91,
	0xc0804fc5, 0xdc61a220, 0x775a694b, 0x121c161a,
	0x93e20aba, 0xa0c0e52a, 0x223c43e0, 0x1b121d17,
	0x090e0b0d, 0x8bf2adc7, 0xb62db9a8, 0x1e14c8a9,
	0xf1578519, 0x75af4c07, 0x99eebbdd, 0x7fa3fd60,
	0x01f79f26, 0x725cbcf5, 0x6644c53b, 0xfb5b347e,
	0x438b7629, 0x23cbdcc6, 0xedb668fc, 0xe4b863f1,
	0x31d7cadc, 0x63421085, 0x97134022, 0xc6842011,
	0x4a857d24, 0xbbd2f83d, 0xf9ae1132, 0x29c76da1,
	0x9e1d4b2f, 0xb2dcf330, 0x860dec52, 0xc177d0e3,
	0xb32b6c16, 0x70a999b9, 0x9411fa48, 0xe9472264,
	0xfca8c48c, 0xf0a01a3f, 0x7d56d82c, 0x3322ef90,
	0x4987c74e, 0x38d9c1d1, 0xca8cfea2, 0xd498360b,
	0xf5a6cf81, 0x7aa528de, 0xb7da268e, 0xad3fa4bf,
	0x3a2ce49d, 0x78500d92, 0x5f6a9bcc, 0x7e546246,
	0x8df6c213, 0xd890e8b8, 0x392e5ef7, 0xc382f5af,
	0x5d9fbe80, 0xd0697c93, 0xd56fa92d, 0x25cfb312,
	0xacc83b99, 0x1810a77d, 0x9ce86e63, 0x3bdb7bbb,
	0x26cd0978, 0x596ef418, 0x9aec01b7, 0x4f83a89a,
	0x95e6656e, 0xffaa7ee6, 0xbc2108cf, 0x15efe6e8,
	0xe7bad99b, 0x6f4ace36, 0x9fead409, 0xb029d67c,
	0xa431afb2, 0x3f2a3123, 0xa5c63094, 0xa235c066,
	0x4e7437bc, 0x82fca6ca, 0x90e0b0d0, 0xa73315d8,
	0x04f14a98, 0xec41f7da, 0xcd7f0e50, 0x91172ff6,
	0x4d768dd6, 0xef434db0, 0xaacc544d, 0x96e4df04,
	0xd19ee3b5, 0x6a4c1b88, 0x2cc1b81f, 0x65467f51,
	0x5e9d04ea, 0x8c015d35, 0x87fa7374, 0x0bfb2e41,
	0x67b35a1d, 0xdb9252d2, 0x10e93356, 0xd66d1347,
	0xd79a8c61, 0xa1377a0c, 0xf8598e14, 0x13eb893c,
	0xa9ceee27, 0x61b735c9, 0x1ce1ede5, 0x477a3cb1,
	0xd29c59df, 0xf2553f73, 0x141879ce, 0xc773bf37,
	0xf753eacd, 0xfd5f5baa, 0x3ddf146f, 0x447886db,
	0xafca81f3, 0x68b93ec4, 0x24382c34, 0xa3c25f40,
	0x1d1672c3, 0xe2bc0c25, 0x3c288b49, 0x0dff4195,
	0xa8397101, 0x0c08deb3, 0xb4d89ce4, 0x566490c1,
	0xcb7b6184, 0x32d570b6, 0x6c48745c, 0xb8d04257,
};
