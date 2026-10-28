#ifndef TANCRYPT_AESTYPES_HPP
#define TANCRYPT_AESTYPES_HPP

struct evp_cipher_st;
typedef evp_cipher_st EVP_CIPHER;

namespace tancrypt
{

  namespace AES
  {
    class _aestype
    {
      public:
        const static EVP_CIPHER* cphs[6];

      private:
        _aestype() { }
    };
    enum class Type : int
    {
      CBC128 = 0,
      GCM128 = 1,
      CBC192 = 2,
      GCM192 = 3,
      CBC256 = 4,
      GCM256 = 5
    };
  }

}
#endif
