.syntax unified
.thumb
.text

.align 3
// void CM0_sBOX_AES_decrypt(uint8_t* rk, const uint8_t* in, uint8_t* out, size_t rounds) {
.global CM0_sBOX_AES_decrypt
.type   CM0_sBOX_AES_decrypt,%function
CM0_sBOX_AES_decrypt:
	push {r4-r7, lr}

	b . // not yet

	pop {r4-r7, pc}

