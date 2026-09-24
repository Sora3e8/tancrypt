#ifndef TANCRYPT_RSA_PKIC_HPP
#define TANCRYPT_RSA_PKIC_HPP

#include "dutils.hpp"
#include <string>

extern "C" struct evp_pkey_st;

namespace tancrypt
{
  namespace RSA
  {
    class pkic
    {
      public:
        pkic();
        ~pkic();

        pkic(pkic&& other) noexcept;
        pkic& operator=(pkic&& other) noexcept;

        // PKIC pair generators
        void generate_keypair(size_t length);

        operator evp_pkey_st*();
        bool isInitialized();

        // DER loaders
        void loadPrivDER(unsigned char* DER, size_t size);
        void loadPubDER(unsigned char* DER, size_t size);
        void loadPrivDER(dutils::dbuffer& DER);
        void loadPubDER(dutils::dbuffer& DER);

        // DER getters
        dutils::dbuffer getPrivDER();
        dutils::dbuffer getPubDER();

        // PEM loaders
        void importPEM(const char* file);
        void loadPEMStr(const char* PEM);

        // PEM string getters
        std::string getPubPEM();
        std::string getPrivPEM();
        std::string getBundlePEM();

        // PEM exporters
        void exportPrivPEM(const char* file);
        void exportPubPEM(const char* file);
        void exportBundlePEM(const char* file);

        size_t getBits();

      private:
        ::evp_pkey_st* key_container = nullptr;
    };
  } // namespace RSA
} // namespace tancrypt
#endif
