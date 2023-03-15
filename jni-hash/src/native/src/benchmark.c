#include <stdio.h>
#include "sha256.h"
#include <time.h>
#include <openssl/evp.h>
#include "SimpleFIPS202.h"
#include "custom_fips202/fips202.h"

#define ITERATIONS 100000000
#define WARMUP_ITERATIONS 50000000

unsigned char data[128];
unsigned char result[32];

#define BENCHMARK(fname, name, function)                                                                       \
    void fname()                                                                                               \
    {                                                                                                          \
        for (int i = 0; i < WARMUP_ITERATIONS; i++)                                                            \
        {                                                                                                      \
            (function);                                                                                        \
        }                                                                                                      \
        struct timespec start, stop;                                                                           \
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);                                                       \
        for (uint32_t i = 0; i < ITERATIONS; i++)                                                              \
        {                                                                                                      \
            (function);                                                                                        \
        }                                                                                                      \
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);                                                        \
        long long unsigned time = ((stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3); \
        printf("%s: \t\t%llu\n", name, time);                                                                  \
    }

EVP_MD_CTX *evp_md_ctx = NULL;
const EVP_MD *shake256_md = NULL;
void openssl_shake256(unsigned char *out, unsigned long long outlen,
                      const unsigned char *in, unsigned long long inlen)
{
    if (evp_md_ctx == NULL)
    {
        evp_md_ctx = EVP_MD_CTX_new();
        shake256_md = EVP_shake256();
    }

    EVP_DigestInit_ex(evp_md_ctx, shake256_md, NULL);

    EVP_DigestUpdate(evp_md_ctx, in, inlen);
    EVP_DigestFinalXOF(evp_md_ctx, out, outlen);
}

void openssl_sha256_ctx(const unsigned char *in, unsigned int inlen, unsigned char *out)
{
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in, inlen);
    SHA256_Final(out, &ctx);
}

BENCHMARK(sha2_openssl_direct_52, "SHA256 OpenSSL direct 52 bytes", SHA256(data, 52, result))
BENCHMARK(sha2_openssl_direct_96, "SHA256 OpenSSL direct 96 bytes", SHA256(data, 96, result))
BENCHMARK(sha2_openssl_direct_128, "SHA256 OpenSSL direct 128 bytes", SHA256(data, 128, result))

BENCHMARK(sha2_openssl_ctx_52, "SHA256 OpenSSL with CTX 52 bytes", openssl_sha256_ctx(data, 52, result))
BENCHMARK(sha2_openssl_ctx_96, "SHA256 OpenSSL with CTX 96 bytes", openssl_sha256_ctx(data, 96, result))
BENCHMARK(sha2_openssl_ctx_128, "SHA256 OpenSSL with CTX 128 bytes", openssl_sha256_ctx(data, 128, result))

BENCHMARK(sha2_openssl_fixed_padding_52, "SHA256 OpenSSL Fixed padding 52 bytes", sha2_256_length(_416, data, result))
BENCHMARK(sha2_openssl_fixed_padding_96, "SHA256 OpenSSL Fixed padding 96 bytes", sha2_256_length(_768, data, result))
BENCHMARK(sha2_openssl_fixed_padding_128, "SHA256 OpenSSL Fixed padding 128 bytes", sha2_256_length(_1024, data, result))

BENCHMARK(sha2_openssl_custom_padding_52, "SHA256 OpenSSL Custom padding 52 bytes", sha2_256_custom_padding(data, 52, result))
BENCHMARK(sha2_openssl_custom_padding_96, "SHA256 OpenSSL Custom padding 96 bytes", sha2_256_custom_padding(data, 96, result))
BENCHMARK(sha2_openssl_custom_padding_128, "SHA256 OpenSSL Custom padding 128 bytes", sha2_256_custom_padding(data, 128, result))

BENCHMARK(shake_custom_52, "SHAKE256_256 Custom 52 bytes", custom_fips202_shake256(result, 32, data, 52))
BENCHMARK(shake_custom_96, "SHAKE256_256 Custom 96 bytes", custom_fips202_shake256(result, 32, data, 96))
BENCHMARK(shake_custom_128, "SHAKE256_256 Custom 128 bytes", custom_fips202_shake256(result, 32, data, 128))

BENCHMARK(shake_openssl_52, "SHAKE256_256 OpenSSL 52 bytes", openssl_shake256(result, 32, data, 52))
BENCHMARK(shake_openssl_96, "SHAKE256_256 OpenSSL 96 bytes", openssl_shake256(result, 32, data, 96))
BENCHMARK(shake_openssl_128, "SHAKE256_256 OpenSSL 128 bytes", openssl_shake256(result, 32, data, 128))

BENCHMARK(shake_xkcp_52, "SHAKE256_256 XKCP 52 bytes", SHAKE256(result, 32, data, 52))
BENCHMARK(shake_xkcp_96, "SHAKE256_256 XKCP 96 bytes", SHAKE256(result, 32, data, 96))
BENCHMARK(shake_xkcp_128, "SHAKE256_256 XKCP 128 bytes", SHAKE256(result, 32, data, 128))

int main()
{
    for (int i = 0; i < 128; i++)
    {
        data[i] = i;
    }

    sha2_openssl_direct_52();
    sha2_openssl_ctx_52();
    sha2_openssl_fixed_padding_52();
    sha2_openssl_custom_padding_52();

    sha2_openssl_direct_96();
    sha2_openssl_ctx_96();
    sha2_openssl_fixed_padding_96();
    sha2_openssl_custom_padding_96();

    sha2_openssl_direct_128();
    sha2_openssl_ctx_128();
    sha2_openssl_fixed_padding_128();
    sha2_openssl_custom_padding_128();

    shake_custom_52();
    shake_custom_96();
    shake_custom_128();

    shake_openssl_52();
    shake_openssl_96();
    shake_openssl_128();

    shake_xkcp_52();
    shake_xkcp_96();
    shake_xkcp_128();
}
