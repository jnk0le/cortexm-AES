.syntax unified
.thumb
.text

.align 3
// void CM0_sBOX_AES_256_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global CM0_sBOX_AES_256_keyschedule_enc
.type   CM0_sBOX_AES_256_keyschedule_enc,%function
CM0_sBOX_AES_256_keyschedule_enc:
	push {r4-r7, lr}

	b . // not yet

	pop {r4-r7, pc}

