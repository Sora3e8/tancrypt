#include "pkic.hpp"
#include <cstddef>
#include <fstream>
#include <ios>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sstream>
#include <stdexcept>

namespace tancrypt
{
  namespace RSA
  {
    pkic::pkic() { }

    pkic::~pkic()
    {
      if (key_container != nullptr)
      {
        EVP_PKEY_free(key_container);
        key_container = nullptr;
      }
    }

    pkic::pkic(pkic&& other) noexcept
    {
      if (this->key_container != nullptr) EVP_PKEY_free(key_container);
      this->key_container = other.key_container;
      other.key_container = nullptr;
    }

    pkic& pkic::operator=(pkic&& other) noexcept
    {
      if (this != &other)
      {
        if (this->key_container != nullptr) EVP_PKEY_free(key_container);
        this->key_container = other.key_container;
        other.key_container = nullptr;
      }
      return *this;
    }

    bool pkic::isInitialized()
    {
      return (key_container != nullptr);
    }

    pkic::operator evp_pkey_st*()
    {
      return key_container;
    }

    void pkic::generate_keypair(size_t length)
    {
      if (key_container != nullptr) EVP_PKEY_free(key_container);
      key_container = EVP_RSA_gen(length);
    }

    void pkic::loadPrivDER(unsigned char* DER, size_t size)
    {
      const unsigned char* content = DER;
      d2i_PrivateKey(EVP_PKEY_RSA, &key_container, &content, size);

      if (key_container == NULL)
      {
        unsigned long _err = ERR_get_error();
        throw std::runtime_error("[tancrypt::RSA::pkic::loadPrivDER] Failed to load privkey from DER.\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
      }
    }

    void pkic::loadPrivDER(dutils::dbuffer& DER)
    {
      const unsigned char* content = DER.data();
      d2i_PrivateKey(EVP_PKEY_RSA, &key_container, &content, DER.size());

      if (key_container == NULL)
      {
        unsigned long _err = ERR_get_error();
        throw std::runtime_error("[tancrypt::RSA::pkic::loadPrivDER] Failed to load privkey from DER.\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
      }
    }

    void pkic::loadPubDER(unsigned char* DER, size_t size)
    {
      const unsigned char* content = DER;
      d2i_PublicKey(EVP_PKEY_RSA, &key_container, &content, size);

      if (key_container == nullptr)
      {
        unsigned long _err = ERR_get_error();
        throw std::runtime_error("[tancrypt::RSA::pkic::loadPubDER] Failed to load pubkey from DER.\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
      }
    }

    void pkic::loadPubDER(dutils::dbuffer& DER)
    {
      const unsigned char* content = DER.data();
      d2i_PublicKey(EVP_PKEY_RSA, &key_container, &content, DER.size());

      if (key_container == nullptr)
      {
        unsigned long _err = ERR_get_error();
        throw std::runtime_error("[tancrypt::RSA::pkic::loadPubDER] Failed to load pubkey from DER.\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
      }
    }

    size_t pkic::getBits()
    {
      int res = EVP_PKEY_get_bits(key_container);
      return ((res > -1) ? res : 0);
    }

    dutils::dbuffer pkic::getPrivDER()
    {
      if (key_container == nullptr)
      {
        throw std::logic_error("[tancrypt::RSA::pkic::getPrivDER] The key container was not initialized.");
      }

      int key_len = i2d_PrivateKey(key_container, NULL);

      if (key_len < 0)
      {
        unsigned long _err = ERR_get_error();
        std::cerr << "[tancrpyt::RSA::pkic::getPrivDER] Could not get DER of the privkey.\n"
                  << "Error " << _err << ", " << ERR_reason_error_string(_err) << std::endl;

        return { };
      }

      dutils::dbuffer key_der(key_len);
      unsigned char* pkey = key_der.data();
      int _bytes_written = i2d_PrivateKey(key_container, &pkey);

      if (_bytes_written != key_len) throw std::runtime_error("\033[31m[tancrypt::RSA::pkic::getPrivDER] Critical error, buffer corrupted.\nBuffer size expected: " + std::to_string(key_len) + "\nBuffer written: " + std::to_string(_bytes_written) + "\033[0m");

      return key_der;
    }

    dutils::dbuffer pkic::getPubDER()
    {
      if (key_container == nullptr)
      {
        throw std::logic_error("[tancrypt::RSA::pkic::getPubDER] The key container was not initialized.");
      }

      int key_len = i2d_PublicKey(key_container, NULL);

      if (key_len <= 0)
      {
        unsigned long _err = ERR_get_error();
        std::cerr << "[tancrypt::RSA::pkic::getPubDER] Could not get DER of the pubkey.\n"
                  << "Error " << _err << ", " << ERR_reason_error_string(_err) << std::endl;
        return { };
      }

      dutils::dbuffer key_der(key_len);
      unsigned char* pkey = key_der.data();
      int _bytes_written = i2d_PublicKey(key_container, &pkey);

      if (_bytes_written != key_len) throw std::runtime_error("\033[31m[tancrypt::RSA::pkic::getPubDER] Critical error, buffer corrupted.\nBuffer size expected: " + std::to_string(key_len) + "\nBuffer written: " + std::to_string(_bytes_written) + "\033[0m");

      return key_der;
    }

    void pkic::loadPEMStr(const char* PEM)
    {
      BIO* bio = BIO_new_mem_buf(PEM, strlen(PEM));

      if (!bio)
      {
        unsigned long _err = ERR_get_error();
        throw std::runtime_error("[tancrypt::RSA::pkic::loadPEMStr] Could not allocate buffer.\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
      }

      ::evp_pkey_st* tmp_key = nullptr;
      tmp_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
      BIO_reset(bio);

      if (tmp_key != nullptr) key_container = tmp_key;
      if (tmp_key == nullptr) tmp_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
      if (tmp_key != nullptr) key_container = tmp_key;
      if (tmp_key == nullptr) std::cerr << "[tancrypt::RSA::pkic::loadPEMStr] Failed to read PEM, \ncheck if the provided PEM string is valid." << std::endl;

      BIO_free(bio);
    }

    void pkic::importPEM(const char* file)
    {
      std::fstream pem_file(file, std::ios_base::in);

      if (!pem_file)
      {
        std::cerr << "[tancrypt::RSA::pkic::importPEM] Could not open file: " << file << "\nError " << errno << ", " << strerror(errno) << std::endl;
        return;
      }

      std::stringstream pem_str;
      pem_str << pem_file.rdbuf();
      pem_file.close();

      const std::string str_tmp = pem_str.str();
      const char* pem_str2 = str_tmp.c_str();
      loadPEMStr(pem_str2);
    }

    std::string pkic::getPrivPEM()
    {
      if (key_container == nullptr)
      {
        throw std::logic_error("[tancrypt::RSA::pkic::getPrivPEM] The key container was not initialized.");
      }

      BIO* bio = BIO_new(BIO_s_mem());

      if (!bio)
      {
        unsigned long _err = ERR_get_error();
        throw std::runtime_error("[tancrypt::RSA::pkic::getPrivPEM] Could not allocate buffer.\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
      }

      if (PEM_write_bio_PrivateKey(bio, key_container, NULL, NULL, 0, NULL, NULL) != 1)
      {
        unsigned long _err = ERR_get_error();
        BIO_free(bio);
        std::cerr << "[tancrypt::RSA::pkic::getPrivPEM] Could not retrieve PEM.\n"
                  << "Error " << _err << ", " << ERR_reason_error_string(_err) << std::endl;

        return "";
      }

      int len = BIO_pending(bio);

      if (len <= 0)
      {
        unsigned long _err = ERR_get_error();
        BIO_free(bio);
        std::cerr << "[tancrypt::RSA::pkic::getPrivPEM] Could not retrieve PEM.\n"
                  << "Error " << _err << ", " << ERR_reason_error_string(_err) << std::endl;

        return "";
      }

      std::string pem_str(len, '\0');
      BIO_read(bio, &pem_str[0], len);
      BIO_free(bio);

      return pem_str;
    }

    std::string pkic::getPubPEM()
    {
      if (key_container == nullptr)
      {
        throw std::logic_error("[tancrypt::RSA::pkic::getPubPEM] The key container was not initialized.");
      }

      BIO* bio = BIO_new(BIO_s_mem());

      if (!bio)
      {
        unsigned long _err = ERR_get_error();
        throw std::runtime_error("[tancrypt::RSA::getPubPEM] Could not allocate buffer.\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
      }

      if (PEM_write_bio_PUBKEY(bio, key_container) != 1)
      {
        unsigned long _err = ERR_get_error();
        BIO_free(bio);
        std::cerr << "[tancrypt::RSA::pkic::getPubPEM] Could not retrieve PEM.\n"
                  << "Error " << _err << ", " << ERR_reason_error_string(_err) << std::endl;

        return "";
      }

      int len = BIO_pending(bio);
      if (len <= 0)
      {
        unsigned long _err = ERR_get_error();
        BIO_free(bio);
        std::cerr << "[tancrypt::RSA::pkic::getPubPEM] Could not retrieve PEM.\n"
                  << "Error " << _err << ", " << ERR_reason_error_string(_err) << std::endl;

        return "";
      }

      std::string pem_str(len, '\0');
      BIO_read(bio, &pem_str[0], len);
      BIO_free(bio);

      return pem_str;
    }

    std::string pkic::getBundlePEM()
    {
      return getPubPEM() + getPrivPEM();
    }

    void pkic::exportPrivPEM(const char* file)
    {
      std::fstream pem_out(file, std::ios_base::out);

      if (!pem_out)
      {
        std::cerr << "[tancrypt::RSA::pkic::exportPrivPEM] Could not open file: " << file << "\nError " << errno << ", " << strerror(errno) << std::endl;
        return;
      }

      pem_out << getPrivPEM();
      pem_out.close();
    }

    void pkic::exportPubPEM(const char* file)
    {
      std::fstream pem_out(file, std::ios_base::out);

      if (!pem_out)
      {
        std::cerr << "[tancrypt::RSA::pkic::exportPubPEM] Could not open file: " << file << "\nError " << errno << ", " << strerror(errno) << std::endl;
        return;
      }

      pem_out << getPubPEM();
      pem_out.close();
    }

    void pkic::exportBundlePEM(const char* file)
    {
      std::fstream pem_out(file, std::ios_base::out);

      if (!pem_out)
      {
        std::cerr << "[tancrypt::RSA::pkic::exportBundlePEM] Could not open file: " << file << "\nError " << errno << ", " << strerror(errno) << std::endl;
        return;
      }

      pem_out << getBundlePEM();
      pem_out.close();
    }
  }
}
