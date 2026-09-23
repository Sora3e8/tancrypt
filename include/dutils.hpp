#ifndef DUTILS_HPP
#define DUTILS_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace dutils
{
  class dbuffer
  {
    public:
      dbuffer() { };
      ~dbuffer() { delete[] _data; };
      size_t _size = 0;
      unsigned char* _data = nullptr;

      dbuffer(const dbuffer& other) noexcept
      {
        this->_size = other.size();
        _data = new unsigned char[other.size()];
        memcpy(this->_data, other._data, other.size());
      }

      dbuffer(dbuffer&& other) noexcept
      {
        if (this->_data != nullptr) delete[] _data;
        this->_size = other._size;
        this->_data = other._data;
        other._data = nullptr;
      }

      dbuffer& operator=(const dbuffer& other) noexcept
      {
        if (this != &other)
        {
          if (this->_data != nullptr) delete[] _data;
          this->_size = other.size();
          this->_data = new unsigned char[other.size()];
          memcpy(this->_data, other._data, other.size());
        }

        return *this;
      }
      dbuffer& operator=(dbuffer&& other) noexcept
      {
        if (this != &other)
        {
          delete[] _data;
          _data = other._data;
          _size = other._size;
          other._data = nullptr;
          other._size = 0;
        }
        return *this;
      }
      dbuffer(size_t size)
      {
        this->_size = size;
        this->_data = new unsigned char[_size];
        memset(this->_data, 0, _size);
      }
      dbuffer(const char* src, size_t size)
      {
        this->_size = size;
        this->_data = new unsigned char[_size];
        memcpy(this->_data, src, _size);
      }

      dbuffer(const unsigned char* src, size_t size)
      {
        this->_size = size;
        this->_data = new unsigned char[_size];
        memcpy(this->_data, src, _size);
      }

      dbuffer(std::string string)
      {
        this->_size = string.size() + 1;
        this->_data = new unsigned char[_size];
        memcpy(this->_data, string.data(), _size);
      }

      dbuffer(std::string& string)
      {
        this->_size = string.size() + 1;
        this->_data = new unsigned char[_size];
        memcpy(this->_data, string.data(), _size);
      }
      void resize0(size_t size)
      {
        delete[] _data;
        _data = new unsigned char[size];
      }

      void resize(size_t size)
      {
        if (size < 1) return;
        unsigned char* new_data = new unsigned char[size];
        size_t copy_size = std::min(size, _size);
        if (copy_size > 0) memcpy(new_data, this->_data, copy_size);
        if (size > copy_size) memset(new_data + copy_size, 0, size - copy_size);
        delete[] _data;
        _data = new_data;
        this->_size = size;
      }

      dbuffer(std::vector<unsigned char> vector)
      {
        this->_size = vector.size();
        this->_data = new unsigned char[_size];
        memcpy(this->_data, vector.data(), _size);
      };

      dbuffer(std::initializer_list<unsigned char> list)
      {
        this->_size = list.size();
        this->_data = new unsigned char[_size];
        memcpy(this->_data, list.begin(), _size);
      }

      std::string toStr()
      {
        std::string str(begin(), end());
        return str;
      }
      unsigned char* data()
      {
        unsigned char* _data_ptr = this->_data;
        return _data_ptr;
      }
      const unsigned char* data() const
      {
        return this->_data;
      }

      unsigned char* begin()
      {
        unsigned char* _data_ptr = this->_data;
        return _data_ptr;
      }
      unsigned char* end()
      {
        unsigned char* _data_ptr = this->_data;
        return _data_ptr + _size;
      }

      const unsigned char* begin() const
      {

        unsigned char* _data_ptr = this->_data;
        return _data_ptr;
      }
      const unsigned char* end() const
      {
        unsigned char* _data_ptr = this->_data;
        return _data_ptr + _size;
      }

      size_t size() const
      {
        return this->_size;
      }
  };

  static std::string hexStr(const dbuffer& data)
  {

    size_t counter = 0;
    std::stringstream hex_str;
    for (unsigned char val : data)
    {
      hex_str << std::hex << std::setw(2) << std::setfill('0') << (int)val << ((counter < data.size()) ? ":" : "");
      counter++;
    }

    return hex_str.str();
  }

  static std::string hexStr(const char* data, size_t length)
  {

    std::stringstream hex_str;
    for (size_t i = 0; i < length - 1; i++)
    {
      hex_str << std::hex << std::setw(2) << std::setfill('0') << *(uint8_t*)(data + i) << ((i < (length - 1)) ? ":" : "");
    }

    return hex_str.str();
  }

  static std::string hexStr(const unsigned char* data, size_t length)
  {

    std::stringstream hex_str;
    for (size_t i = 0; i < length - 1; i++)
    {
      hex_str << std::hex << std::setw(2) << std::setfill('0') << *(uint8_t*)(data + i) << ((i < (length - 1)) ? ":" : "");
    }

    return hex_str.str();
  }
}
#endif
