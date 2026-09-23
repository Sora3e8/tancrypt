#include "keyc.hpp"
#include "hashtypes.hpp"
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace tancrypt
{
  namespace AES
  {
    keyc::keyc() { }

    keyc::~keyc()
    {
      EVP_CIPHER_free(cipher);
    }

    size_t RefKeylen(AES::Type type)
    {
      const EVP_CIPHER* tmp = EVP_get_cipherbyname(_aesTypeMap().at(type));
      int res = EVP_CIPHER_key_length(tmp);
      return res < 0 ? 0 : res;
    }

    void keyc::setKey(const dutils::dbuffer key)
    {
      _key = key;
    }

    void keyc::setKey(const char* key, size_t size)
    {
      _key = dutils::dbuffer(key, size);
    }

    void keyc::setKey(const unsigned char* key, size_t size)
    {
      _key = dutils::dbuffer(key, size);
    }

    const dutils::dbuffer& keyc::getKey()
    {
      return _key;
    }

    keyc::keyc(const dutils::dbuffer key, AES::Type type)
    {
      setType(type);
      setKey(key);
    }

    keyc::keyc(const char* key, size_t size, AES::Type type)
    {
      setType(type);
      setKey(key, size);
    }

    keyc::keyc(const unsigned char* key, size_t size, AES::Type type)
    {
      setType(type);
      setKey(key, size);
    }

    keyc::keyc(const dutils::dbuffer key, AES::Type type, hashAlg alg)
    {
      setType(type);
      setKey(key);
      setHashAlg(alg);
      setHashEnabled(true);
    }

    keyc::keyc(const unsigned char* key, size_t size, AES::Type type, hashAlg alg)
    {
      setType(type);
      setKey(key, size);
      setHashAlg(alg);
      setHashEnabled(true);
    }

    void keyc::makeRandomKey(size_t size)
    {
      _key.resize0(size);
      RAND_bytes(_key.data(), size);
    }

    keyc keyc::randomKey(size_t size, AES::Type type)
    {
      keyc random_key;
      random_key.makeRandomKey(size);
      random_key.setType(type);

      return random_key;
    }

    keyc keyc::randomKey(size_t size, AES::Type type, hashAlg alg)
    {
      keyc random_key;
      random_key.makeRandomKey(size);
      random_key.setType(type);
      random_key.setHashAlg(alg);
      random_key.setHashEnabled(true);

      return random_key;
    }

    void keyc::setType(AES::Type type)
    {
      if (cipher != nullptr) EVP_CIPHER_free(cipher);
      cipher = EVP_CIPHER_fetch(NULL, _aesTypeMap().at(type), NULL);
    }

    void keyc::setHashEnabled(bool val) { do_hash = val; }

    void keyc::setHashAlg(hashAlg alg) { _alg = alg; }

    bool keyc::getHashEnabled() const { return do_hash; }

    hashAlg keyc::getHashAlg() const { return _alg; }
  }
}
