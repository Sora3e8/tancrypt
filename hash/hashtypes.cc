#include "hashtypes.hpp"
#include <openssl/evp.h>
const EVP_MD* tancrypt::_hashAlg::_hashmds[13] = {
#ifdef OPENSSL_NO_MDC2
  nullptr,
#else
  EVP_mdc2(),
#endif
#ifdef OPENSSL_NO_MD4
  nullptr,
#else
  EVP_md4(),
#endif
#ifdef OPENSSL_NO_MD5
  nullptr,
#else
  EVP_md5(),
#endif
  EVP_sha1(),
  EVP_sha224(),
  EVP_sha256(),
  EVP_sha384(),
  EVP_sha512(),
  EVP_sha512_224(),
  EVP_sha512_256(),
#ifdef OPENSSL_NO_SM3
  nullptr,
#else
  EVP_sm3(),
#endif
#ifdef OPENSSL_NO_BLAKE2
  nullptr,
  nullptr,
#else
  EVP_blake2b512(),
  EVP_blake2s256(),
#endif
};
