#ifndef AES_TESTS_HPP
#define AES_TESTS_HPP

//__attribute__ ((section(".itcm.text"), noinline))
void aes_ecb_test(void);
void aes_cbc_test(void);
void aes_ctr_nist_test(void); // tests against example nist vectors

void aes_cbc_perf_test(void);
void aes_ctr_perf_test(void);

#endif
