#include "hash.hpp"
#include "hashtypes.hpp"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>

namespace tancrypt
{
  dutils::dbuffer hash(const dutils::dbuffer& buffer, hashAlg alg)
  {
    const EVP_MD* md = _hashAlg::_hashmds[(int)alg];

    if (!md)
    {
      unsigned long _err = ERR_get_error();
      throw std::invalid_argument("[pkicxx::hash] Could not load hasing algorithm.\n Error " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
    }
    size_t dlen = EVP_MD_get_size(md);

    dutils::dbuffer buffer_hashed(dlen);
    unsigned int dwritten;
    if (EVP_Digest(buffer.data(), buffer.size(), buffer_hashed.data(), &dwritten, md, NULL) != 1)
    {
      unsigned long _err = ERR_get_error();
      throw std::runtime_error("[tancrypt::hash] Hashing failed.\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
    }

    if (dwritten != dlen)
    {
      throw std::runtime_error("[tancrypt::hash] Critical error, buffer corrupted or incomplete.\nExpected size: " + std::to_string(dlen) + "\nBytes written:" + std::to_string(dwritten));
    }

    return buffer_hashed;
  }

}
