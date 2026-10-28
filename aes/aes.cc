#include "aes.hpp"
#include "hash.hpp"
#include "keyc.hpp"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include <cstdlib>
#include <stdexcept>
#include <string>

namespace tancrypt
{
  dutils::dbuffer AES::encrypt(AES::keyc& key_container, const dutils::dbuffer& buffer)
  {
    dutils::dbuffer hashed_key;

    // Throws error if key_container not ready
    if (key_container.cipher == nullptr) throw std::logic_error("[tancrypt::AES::encrypt] AES::keyc is not initialized");
    int key_size = EVP_CIPHER_key_length(key_container.cipher);

    // Throws error if key unpadded
    if (key_container.getHashEnabled() == false && int(key_container.getKey().size()) < key_size)
    {
      throw std::runtime_error("[tancrypt::AES::encrypt] Bad key, given key size: " + std::to_string(key_container.getKey().size()) + "\nKey size required:" + std::to_string(key_size));
    }

    if (key_container.getHashEnabled() == true)
    {
      hashed_key = tancrypt::hash(key_container.getKey(), key_container.getHashAlg());
    }

    // Random seed size
    int iv_len = EVP_CIPHER_iv_length(key_container.cipher);

    if (iv_len < 0)
    {
      unsigned long _err = ERR_get_error();
      throw std::runtime_error("[tancrypt::AES::encrypt] Could not determine random seed size\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
    }

    // Retrieves block size for padding
    int block_size = EVP_CIPHER_get_block_size(key_container.cipher);

    // Final output buffer
    dutils::dbuffer aes_data(iv_len + buffer.size() + block_size);

    // Retrieves random bytes - if needed
    if (iv_len != 0 && (iv_len < 0 || RAND_bytes(aes_data.data(), iv_len) != 1))
    {
      unsigned long _err = ERR_get_error();
      throw std::runtime_error("[tancrypt::AES::encrypt] Could not generate random seed\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
    }

    // Cipher context initialization
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!ctx)
    {
      unsigned long _err = ERR_get_error();
      throw std::runtime_error("[tancrypt::AES::encrypt] Failed to initialize context\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
    }

    // Points either to key directly or it's hashed buffer version
    const dutils::dbuffer& _key = (key_container.getHashEnabled() ? hashed_key : key_container.getKey());

    if (EVP_CipherInit_ex2(ctx, key_container.cipher, _key.data(), aes_data.data(), 1, NULL) != 1)
    {
      unsigned long _err = ERR_get_error();
      EVP_CIPHER_CTX_free(ctx);

      throw std::runtime_error("[tancrypt::AES::encrypt] Failed to initialize context\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
    }

    // Offset pointer to the buffer where we write the actual encrypted data, only after IV buffer
    unsigned char* out_buf = aes_data.data() + iv_len;

    // 16KB chunk
    int chunk_size = 2048;

    // Irregular chunk size
    int remainder = buffer.size() % chunk_size;

    // Regular chunk count
    int chunk_c = buffer.size() / chunk_size;

    // Tmp chunk size
    int chunk_written = 0;

    // Tracks out buffer position
    long long out_bufpos = 0;

    // Writes regular chunks
    for (int i = 0; i < chunk_c; i++)
    {
      int res = EVP_EncryptUpdate(ctx, out_buf + out_bufpos, &chunk_written, buffer.data() + (chunk_size * i), chunk_size);

      if (res != 1)
      {
        unsigned long _err = ERR_get_error();
        EVP_CIPHER_CTX_free(ctx);

        throw std::runtime_error("[tancrypt::AES::encrypt] Critical error when writing buffer\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
      }

      // Proceeds buffer position
      out_bufpos += chunk_written;
    }

    // Writes irregular chunk
    if (remainder > 0)
    {
      int res = EVP_EncryptUpdate(ctx, out_buf + out_bufpos, &chunk_written, buffer.data() + (chunk_c * chunk_size), remainder);

      if (res != 1)
      {
        unsigned long _err = ERR_get_error();
        EVP_CIPHER_CTX_free(ctx);

        throw std::runtime_error("[tancrypt::AES::encrypt] Critical error when writing buffer\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
      }

      // Proceeds buffer position
      out_bufpos += chunk_written;
    }

    // Final padding
    if (EVP_CipherFinal_ex(ctx, out_buf + out_bufpos, &chunk_written) != 1)
    {
      unsigned long _err = ERR_get_error();
      EVP_CIPHER_CTX_free(ctx);

      throw std::runtime_error("[tancrypt::AES::encrypt] Critical error when writing buffer\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
    }

    // Proceeds the buffer position
    out_bufpos += chunk_written;

    // Final context clean up
    EVP_CIPHER_CTX_free(ctx);

    // Truncates the overallocated blocks
    aes_data.resize(iv_len + out_bufpos);

    return aes_data;
  }

  dutils::dbuffer AES::decrypt(AES::keyc& key_container, const dutils::dbuffer& buffer)
  {
    dutils::dbuffer hashed_key;

    // Throws error if key_container not ready
    if (key_container.cipher == nullptr) throw std::logic_error("[tancrypt::AES::decrypt] AES::keyc is not initialized");
    int key_size = EVP_CIPHER_key_length(key_container.cipher);

    // Throws error if key unpadded
    if (key_container.getHashEnabled() == false && int(key_container.getKey().size()) < key_size)
    {
      throw std::runtime_error("[tancrypt::AES::decrypt] Bad key, given key size: " + std::to_string(key_container.getKey().size()) + "\nKey size required:" + std::to_string(key_size));
    }

    if (key_container.getHashEnabled() == true)
    {
      hashed_key = tancrypt::hash(key_container.getKey(), key_container.getHashAlg());
    }

    // Random seed size
    int iv_len = EVP_CIPHER_iv_length(key_container.cipher);

    if (iv_len < 0)
    {
      unsigned long _err = ERR_get_error();
      throw std::runtime_error("[tancrypt::AES::decrypt] Could not determine random seed size\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
    }

    // Retrieves block size for padding
    int block_size = EVP_CIPHER_get_block_size(key_container.cipher);

    // Final output buffer
    dutils::dbuffer aes_data(block_size + iv_len);

    // Cipher context initialization
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!ctx)
    {
      unsigned long _err = ERR_get_error();
      throw std::runtime_error("[tancrypt::AES::decrypt] Failed to initialize context\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
    }

    // Points either to key directly or it's hashed buffer version
    const dutils::dbuffer& _key = (key_container.getHashEnabled() ? hashed_key : key_container.getKey());

    if (EVP_CipherInit_ex2(ctx, key_container.cipher, _key.data(), buffer.data(), 0, NULL) != 1)
    {
      unsigned long _err = ERR_get_error();
      EVP_CIPHER_CTX_free(ctx);
      throw std::runtime_error("[tancrypt::AES::decrypt] Failed to initialize context\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
    }

    // Offset pointer to the buffer where we write the actual encrypted data, only after IV buffer
    unsigned char* out_buf = aes_data.data();
    const unsigned char* input_buf = buffer.data() + iv_len;

    // 16KB chunk
    size_t chunk_size = 2048;

    // Irregular chunk size
    size_t remainder = (buffer.size() - iv_len) % chunk_size;

    // Regular chunk count
    size_t chunk_c = (buffer.size() - iv_len) / chunk_size;

    // Tmp chunk size
    int chunk_written = 0;

    // Tracks out buffer position
    long long out_bufpos = 0;

    // Writes regular chunks
    for (int i = 0; i < chunk_c; i++)
    {
      int res = EVP_DecryptUpdate(ctx, out_buf + out_bufpos, &chunk_written, input_buf + (chunk_size * i), chunk_size);

      if (res != 1)
      {
        unsigned long _err = ERR_get_error();
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("[tancrypt::AES::decrypt] Critical error when writing buffer\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
      }

      // Proceeds buffer position
      out_bufpos += chunk_written;
    }

    // Writes irregular chunk
    if (remainder > 0)
    {
      int res = EVP_DecryptUpdate(ctx, out_buf + out_bufpos, &chunk_written, input_buf + (chunk_c * chunk_size), remainder);

      if (res != 1)
      {
        unsigned long _err = ERR_get_error();
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("[tancrypt::AES::decrypt] Critical error when writing buffer\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
      }

      // Proceeds buffer position
      out_bufpos += chunk_written;
    }

    // Final padding
    if (EVP_CipherFinal_ex(ctx, out_buf + out_bufpos, &chunk_written) != 1)
    {
      unsigned long _err = ERR_get_error();
      EVP_CIPHER_CTX_free(ctx);
      throw std::runtime_error("[tancrypt::AES::decrypt] Critical error when writing buffer\nError " + std::to_string(_err) + ", " + ERR_reason_error_string(_err));
    }

    // Proceeds the buffer position
    out_bufpos += chunk_written;

    // Final context clean up
    EVP_CIPHER_CTX_free(ctx);

    // Truncates the overallocated blocks and outputs buffer
    aes_data.resize(out_bufpos);

    return aes_data;
  }

  dutils::dbuffer AES::getNonce(const dutils::dbuffer& buffer, AES::Type type)
  {
    size_t len = EVP_CIPHER_iv_length(_aestype::cphs[(int)type]);

    switch ((len == 0) | (len < 0) * 2)
    {
      case 0: break;
      case 1: throw std::logic_error("[tancrypt::AES::getNonce] Not applicable for given cipher type, nonce not used."); break;
      case 2: throw std::runtime_error("[tancrypt::AES::getNonce] Critical error, invalid cipher type or nonce not used."); break;
    }

    dutils::dbuffer nonce_buffer(len);
    std::copy(buffer.data(), buffer.data() + len, nonce_buffer.data());

    return nonce_buffer;
  }

}
