#include "hashtypes.hpp"
#include <openssl/evp.h>
const EVP_MD* tancrypt::_hashAlg::_hashmds[13] = {
  EVP_mdc2(),
  EVP_md4(),
  EVP_md5(),
  EVP_sha1(),
  EVP_sha224(),
  EVP_sha256(),
  EVP_sha384(),
  EVP_sha512(),
  EVP_sha512_224(),
  EVP_sha512_256(),
  EVP_sm3(),
  EVP_blake2b512(),
  EVP_blake2s256()
};
