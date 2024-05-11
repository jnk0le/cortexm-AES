#if __riscv && (__riscv_xlen == 32)

.text

// void QKv2_sBOX_AES192_keyschedule_enc(uint8_t *rk, const uint8_t *key) {
.global QKv2_sBOX_AES192_keyschedule_enc
.type   QKv2_sBOX_AES192_keyschedule_enc,%function
QKv2_sBOX_AES192_keyschedule_enc:
	ret


#endif
