#ifndef TANCRYPT_AES_HPP
#define TANCRYPT_AES_HPP

#include "aestypes.hpp"
#include "dutils.hpp"
#include "keyc.hpp"

namespace tancrypt
{
  namespace AES
  {
    class keyc;
    dutils::dbuffer encrypt(AES::keyc& key_container, const dutils::dbuffer& buffer);
    dutils::dbuffer decrypt(AES::keyc& key_container, const dutils::dbuffer& buffer);
    dutils::dbuffer getNonce(const dutils::dbuffer& buffer, AES::Type type);
  }
}

#endif
