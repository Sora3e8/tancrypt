#ifndef TANCRYPT_AES_KEYC
#define TANCRYPT_AES_KEYC

#include "aestypes.hpp"
#include "dutils.hpp"
#include "hashtypes.hpp"

namespace tancrypt
{
  namespace AES
  {

    size_t RefKeylen(AES::Type type);

    class keyc
    {
      public:
        keyc();
        ~keyc();

        keyc(const dutils::dbuffer key, AES::Type type);
        keyc(const char* key, size_t size, AES::Type type);
        keyc(const unsigned char* key, size_t size, AES::Type type);
        keyc(const dutils::dbuffer key, AES::Type type, hashAlg alg);
        keyc(const char* key, size_t size, AES::Type type, hashAlg alg);
        keyc(const unsigned char* key, size_t size, AES::Type type, hashAlg alg);
        static keyc randomKey(size_t key_length, AES::Type type);
        static keyc randomKey(size_t key_length, AES::Type type, hashAlg alg);

        void setType(AES::Type type);
        void setHashAlg(hashAlg alg);
        void makeRandomKey(size_t size);
        void setHashEnabled(bool val);
        hashAlg getHashAlg() const;
        bool getHashEnabled() const;
        void setKey(const dutils::dbuffer key);
        void setKey(const char* key, size_t size);
        void setKey(const unsigned char* key, size_t size);
        const dutils::dbuffer& getKey();
        const EVP_CIPHER* cipher = nullptr;
        dutils::dbuffer _key;

      private:
        hashAlg _alg = hashAlg::SHA256;
        bool do_hash = false;
    };
  } // namespace AES
} // namespace tancrypt
#endif
