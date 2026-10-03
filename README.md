# Tancrypt
[![Build](https://github.com/Sora3e8/tancrypt/actions/workflows/release-build.yml/badge.svg)](https://github.com/Sora3e8/tancrypt/actions/workflows/release-build.yml)  
Simple cryptographic C++ wrapper library.  
Wraps around the OpenSSL EVP C api to allow easy keypair generation with simplfied API.  
Provides basic cryptographic operations and comes with custom managed data buffer.

Documentation: https://sora3e8.github.io/tancrypt


Features
--------------------------------------------------------------------------
- RSA keyc container and management
- RSA encrypt, decrypt, sign and verify
- AES key container
- AES encrypt, decrypt
- Custom data buffer

Dependencies
--------------------------------------------------------------------------
- OpenSSL3.0+

Build
--------------------------------------------------------------------------
```bash
git clone https://github.com/Sora3e8/tancrypt && cd build
cmake -DCMAKE_BUILD_TYPE=Release .. && cmake --build .
```

Example usage
--------------------------------------------------------------------------
```cpp
#include <iostream>
#include "tancrypt/rsa.hpp"

int main()
{
  // Makes life easier 
  using namespace tancrypt;

  // Keypair generation
  RSA::pkic key;
  key.generate_keypair(2048);

  // Preparing example buffer from string
  dutils::dbuffer data_in("Hewwo, I am secret ^.^");

  // Encrypting data
  dutils::dbuffer encrypted_buffer = RSA::encrypt(key,data_in);

  // You can check the results via helper function dutils::hexStr
  std::cout << "Original:" << data_in.toStr()<< std::endl;
  std::cout << "Original(hex):" << dutils::hexStr(data_in) << std::endl;
  std::cout << "Encrypted:" << encrypted_buffer.toStr() << std::endl;
  std::cout << "Encrypted(hex):" << dutils::hexStr(encrypted_buffer) << std::endl;

  return 0;
}
```
