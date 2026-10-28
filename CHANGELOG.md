## 2.0.0 (2026-10-28)

### BREAKING CHANGE

- hashAlg::RSA_SHA1 was removed as it is the same as hashAlg::SHA1, if used the enum must be replace as this one is no longer valid

### Fix

- **hash**: add hash algorithm availability macros
- **pkic**: patch overgen edge cases
- **dbuffer**: patch class re-init edgecases
- **build**: fix missing link for asan on linux
- **ci-cd-build**: fix propagation of windows annotation flags
- **ci-cd-build**: change name of workflow
- **ci-cd-build**: remove redundant c_compiler
- **ci-cd-build**: change build type to envvar
- **ci-cd-build**: change windows build to chocolatey
- **ci-cd-build**: add missing deps setup windows test build
- **ci-build**: fix sudo permission

### Perf

- **hash**: reduce algorithm fetching
- **aes**: reduce cipher fetching

## 1.4.31 (2026-09-27)

### Feat

- Added missing move constructor - Added missing move constructor
- Added new random key generation, various fixes and improvements
- Added 2 new constructors for pkic - Added DER load pubkey and privkey from raw pointer and size
- Added RSA::pkic::getBits
- Added custom data buffer class chore: Updated documentation
- Added getNonce function
- Added AES decrypt function fix: Fixed error in AES encypt function
- Added namespace AES, keyc and encrypt
- Moved the docs fully into docs/ subdir and built
- Added the verify function
- Added sign function and test for the sign function
- Started preparations to implement sign and verify functions
- Changed few things regarding error handling
- Improved error handling, added missing tests for DER loading functions and fixed issues
- Fixed the PEM import
- Improved event handling of tests and added data for testing
- Added decrypt function draft
- Implemented draft for encrypt() function
- Added missing DER Privkey function
- init commit, basic keypair gen and PEM/DER functions

### Fix

- Added missing set _size
- Fixed exception message typo
- Fixed cmake
- Fixed CMake static libs not linking asan
- More fixes of typos in readme and docs
- Fixing stale var names in readme and docs examples
- Fixed some details in tests chore: Updated documentation and readme
- Fixed buffers passed as cpy instead by reference chore: Added AES encryption operations documentation
- Fixed error handler in encrypt function
- Fixed bad refactor in docs
- Fixed bad logging function names, replaced some of the std::cerr by exceptions
- Fixed bad test and removed needless include
- Added consistend logging into tests for all PEMStr loading variants
- Fixed the PEMStr loader and added missing test for it
- Restored tests which got removed by accident during rewrites
- Fixed output buffer trailing zeros in decrypt function
- Added secure padding, fixed error in test

### Refactor

- Name of the project changed pkicxx --> tancrypt feat: Added documentation and many fixes
- Made key_container private, added cursed implicit conversion
- Replaced path inputs std::string --> char*, added tests - currently failing, commented out
- Renamed helper function DERhexStr --> hexStr
- Changed some things regarding the pkicxx::pki, removed bad ref from .clangd
- Did some clean up to complete the splitting into multiple parts
- De-noodlified project structure, improved some parts
- Finished name refactor
- Renamed library pkixcxx --> pkicxx
- Renamed test files, changed type for DER
