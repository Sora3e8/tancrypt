# AES Key Container

## Overview
Is a container for a cryptographic key and AES cipher parameters.

<br/>

## Constructors

### Default constructor
Constructs blank un-initialized instance of AES Key container.  
Allows for a manual initialization, when needed.

<h3><code>AES::keyc()</code></h3>

* **Parameters:**

???+ example

    ```cpp
    using namespace tancrypt

    AES::keyc key;
    key.setType(AES::Type::CBC256);
    key.setKey(buffer);
    key.setHashAlg(algorithm);

    // Needs to be enabled manually if hashing used
    key.setHashEnabled(true); 
    ```

<br/>

### Raw key

!!! Warning
    Please note that when constructing without key hashing,
    you're expected to provide a properly padded key of correct length.
    If you do not want to handle your key padding, use hashing by constructing with `tancrypt::hashAlg`.
!!! Tip
    To get a proper length for AES::Type you can use AES::RefKeylen(AES::Type type)
    
Constructs instance of AES Key container without key hashing.  
When constructing without tancrypt::hashAlg, you must ensure your key data are pre-padded.

<h3><code> AES::keyc(const dutils::dbuffer key,AES::Type type)</code></h3>

* **Parameters:**
    * `#!cpp const dutils::dbuffer key` - Pre-padded key data
    * `#!cpp AES::Type type` - Type of AES algorithm to use


<h3><code> AES::keyc(const char* key,AES::Type type)</code></h3>

* **Parameters:**
    * `#!cpp const char* key` - Pre-padded key data
    * `#!cpp AES::Type type` - Type of AES algorithm to use

<h3><code> AES::keyc(const unsigned char* key,AES::Type type)</code></h3>

* **Parameters:**
    * `#!cpp const unsigned char* key` - Pre-padded key data
    * `#!cpp AES::Type type` - Type of AES algorithm to use


<h3><code> AES::keyc::randomKey(size_t size,AES::Type type)</code></h3>
- Creates a key container with a random key using OpenSSL's RAND_bytes

* **Parameters:**
    * `#!cpp size_t size` - Size of the key (bytes)
    * `#!cpp AES::Type type` - Type of AES algorithm to use

<br/>
<br/>

### Hashed key

!!! Note
    Bear in mind that to avoid possible race conditions and unnecessary state holding,
    the hashing occurs on encryption runtime this may cause this key constructor to be less efficient when encrypting more than once.
    
Constructs instance of AES Key container with key hashing.
Key is automatically hashed on encryption using the given hash algorithm.


<h3><code>AES::keyc(const dutils::dbuffer key,AES::Type type,tancrypt::hashAlg alg)</code></h3>

* **Parameters:**
    * `#!cpp const dutils::dbuffer key` - Key data
    * `#!cpp tancrypt::AES::Type type` - AES algorithm type
    * `#!cpp tancrypt::hashAlg alg` - Hashing algorithm to use on key during encryption
* **Returns:**
    * `#!cpp tancrypt::AES::keyc key`

<h3><code>AES::keyc(const char* key,AES::Type type,tancrypt::hashAlg alg)</code></h3>

* **Parameters:**
    * `#!cpp const char* key` - Key data
    * `#!cpp tancrypt::AES::Type type` - AES algorithm type
    * `#!cpp tancrypt::hashAlg alg` - Hashing algorithm to use on key during encryption
* **Returns:**
    * `#!cpp tancrypt::AES::keyc key`

<h3><code>AES::keyc(const unsigned char* key,AES::Type type,tancrypt::hashAlg alg)</code></h3>

* **Parameters:**
    * `#!cpp const unsigned char* key` - Key data
    * `#!cpp tancrypt::AES::Type type` - AES algorithm type
    * `#!cpp tancrypt::hashAlg alg` - Hashing algorithm to use on key during encryption
* **Returns:**
    * `#!cpp tancrypt::AES::keyc key`

<h3><code>AES::keyc::keyc(size_t size,AES::Type type,tancrypt::hashAlg alg)</code></h3>
- Creates a key container with a random key using OpenSSL's RAND_bytes

* **Parameters:**
    * `#!cpp size_t size` - Size of the key (bytes)
    * `#!cpp tancrypt::AES::Type type` - AES algorithm type
    * `#!cpp tancrypt::hashAlg alg` - Hashing algorithm to use on key during encryption
* **Returns:**
    * `#!cpp tancrypt::AES::keyc key`

</br>

#### AES Type

| Enum Constant | Cryptographic Algorithm | Mode | Key Size |   |
| :---: | :---: | :---: | :---: | :---:  |
| `#!cpp AES::Type::CBC128` | AES-128-CBC | CBC | 128-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="AES::Type::CBC128" data-md-type="copy"></span> |
| `#!cpp AES::Type::CBC192` | AES-192-CBC | CBC | 192-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="AES::Type::CBC192" data-md-type="copy"></span> |
| `#!cpp AES::Type::CBC256` | AES-256-CBC | CBC | 256-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="AES::Type::CBC256" data-md-type="copy"></span> |
| `#!cpp AES::Type::GCM128` | AES-128-GCM | GCM | 128-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="AES::Type::GCM128" data-md-type="copy"></span> |
| `#!cpp AES::Type::GCM192` | AES-192-GCM | GCM | 192-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="AES::Type::GCM192" data-md-type="copy"></span> |
| `#!cpp AES::Type::GCM256` | AES-256-GCM | GCM | 256-bit | <span class="md-code__button"  title="Copy to clipboard" data-clipboard-text="AES::Type::GCM256" data-md-type="copy"></span> |

</br>
</br>

## Methods

### setType
Member method, sets type of AES algorithm.  
Does not corrupt key and can be used even past first initialization.

<h3><code>AES::keyc::setType(AES::Type type)</code></h3>

* **Parameters:**
    * `#!cpp AES::Type type` - AES algorithm type

</br>

### setHashAlg
Sets hashing algorithm to be used for key.  
Does not corrupt key and can be used even past first initialization.

<h3><code>AES::keyc::setHashAlg(tancrypt::hashAlg alg)</code></h3>

* **Parameters:**
    * `#!cpp tancrypt::hashAlg alg` - Hashing algorithm of your choice

</br>

### setKey
Member method, sets key data of the AES Key container.

<h3><code>AES::keyc::setKey(const dutils::dbuffer key)</code></h3>

* **Parameters:**
    * `#!cpp const dutils::dbuffer key` - Key data buffer

<h3><code>AES::keyc::setKey(const char* key)</code></h3>

* **Parameters:**
    * `#!cpp const char* key` - Key data buffer


<h3><code>AES::keyc::setKey(const unsigned char* key)</code></h3>

* **Parameters:**
    * `#!cpp const unsigned char* key` - Key data buffer

</br>
</br>
</br>

### makeRandomKey
!!! Warning
    This does not initialize the key metadata like AES algorithm etc...  
    Only thing changed are allocated size and key content.

Generates new random key in the current buffer

<h3><code>makeRandomKey(size_t size)</code></h3>

* **Parameters:**
    * `size_t size` 

</br>

### getHashAlg
Retrieves currently set hashing algorithm of the AES Key Container

<h3><code>AES::keyc::getHashAlg()</code></h3>

* **Parameters:**
* **Returns:**
    * `tancrypt::hashAlg alg` - Current hashing algorithm

</br>

### getHashEnabled
Retrieves current bool state - is hasing enabled ? true/false

<h3><code>AES::keyc::getHashEnabled()</code></h3>

* **Parameters:**
* **Returns:**
    * `bool hashingEnabled`

### getKey
Retrieves current key data buffer

<h3><code>AES::keyc::getKey()</code></h3>

* **Parameters:**
* **Returns:**
    * `#!cpp const dutils::dbuffer key`
