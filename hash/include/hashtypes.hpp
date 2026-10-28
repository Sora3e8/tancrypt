#ifndef TANCRYPT_HASHTYPES_HPP
#define TANCRYPT_HASHTYPES_HPP

struct evp_md_st;
typedef evp_md_st EVP_MD;

namespace tancrypt
{

  class _hashAlg
  {
    public:
      _hashAlg() { }
      const static EVP_MD* _hashmds[13];
  };

  enum class hashAlg : int
  {
    MDC2 = 0,
    MD4 = 1,
    MD5 = 2,
    SHA1 = 3,
    SHA224 = 5,
    SHA256 = 6,
    SHA384 = 7,
    SHA512 = 8,
    SHA512_224 = 9,
    SHA512_256 = 10,
    SM3 = 11,
    BLAKE2B512 = 12,
    BLAKE2S256 = 13,
  };
}
#endif
