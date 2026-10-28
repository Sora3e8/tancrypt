#include "aestypes.hpp"
#include <openssl/evp.h>

const EVP_CIPHER* tancrypt::AES::_aestype::cphs[6] = {
  EVP_aes_128_cbc(),
  EVP_aes_128_gcm(),
  EVP_aes_192_cbc(),
  EVP_aes_192_gcm(),
  EVP_aes_256_cbc(),
  EVP_aes_256_gcm(),
};
