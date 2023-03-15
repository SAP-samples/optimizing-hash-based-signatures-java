#include <openssl/sha.h>

enum length
{
    _768,
    _1024,
    _416,
    _608,
    _480,
    _440,
    _432,
    _688,
    _376,
    _368,
    _560
};
#define LENGTH_COUNT 11

extern uint32_t input_length[LENGTH_COUNT];
extern uint32_t padding_length[LENGTH_COUNT];
extern uint8_t *paddings[LENGTH_COUNT];

extern uint8_t pad_sha2_256_768[32];

void sha2_256_custom_padding(const unsigned char *in, unsigned int inlen, unsigned char *out);
// Requires the in buffer to fit the required amount of blocks
void sha2_256_custom_padding_no_copy(unsigned char *in, unsigned int inlen, unsigned char *out);

void sha2_256_no_padding(const unsigned char *in, unsigned int in_len, unsigned char *out);
void sha2_256_length(enum length l, const unsigned char *in, unsigned char *out);

void hash_make_string(SHA256_CTX *, unsigned char *);