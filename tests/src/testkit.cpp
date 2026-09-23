#include "hashtypes.hpp"
#include "keyc.hpp"
#include "tancrypt/aes.hpp"
#include "tancrypt/hash.hpp"
#include "tancrypt/rsa.hpp"
#include <functional>
#include <iostream>

int pkicInit(char*[], int)
{
  tancrypt::RSA::pkic key_factory;

  return 0;
}

int aesRandomKey(char*[], int)
{
  using namespace tancrypt;
  AES::keyc key = AES::keyc::randomKey(AES::RefKeylen(AES::Type::CBC256), AES::Type::CBC256);
  key = AES::keyc::randomKey(8, AES::Type::CBC256, hashAlg::SHA256);
  key.makeRandomKey(32);
  key.makeRandomKey(64);

  return 0;
}

int keypairGen(char*[], int)
{
  tancrypt::RSA::pkic key_factory;
  key_factory.generate_keypair(2048);

  return 0;
}

int keypairRegen(char*[], int)
{
  tancrypt::RSA::pkic key_factory;
  key_factory.generate_keypair(2048);
  key_factory.generate_keypair(2048);

  return 0;
}

int keypairMultigen(char*[], int)
{
  tancrypt::RSA::pkic key_factory;

  for (int i = 0; i < 10; i++)
  {
    key_factory.generate_keypair(2048);
  }

  return 0;
}

int getPrivDER(char*[], int)
{
  tancrypt::RSA::pkic key_factory;
  key_factory.generate_keypair(2048);
  dutils::dbuffer priv_der = key_factory.getPrivDER();
  std::cout << dutils::hexStr(priv_der) << std::endl;

  return 0;
}

int getPubDER(char*[], int)
{
  tancrypt::RSA::pkic key_factory;
  key_factory.generate_keypair(2048);
  dutils::dbuffer pub_der = key_factory.getPubDER();
  std::cout << dutils::hexStr(pub_der) << std::endl;

  return 0;
}

int getBits(char*[], int)
{
  tancrypt::RSA::pkic key;
  size_t size_in = 2048;
  key.generate_keypair(size_in);
  size_t size_out = key.getBits();
  if (size_in != size_out) return 1;
  return 0;
}

int loadPrivDER(char*[], int)
{
  tancrypt::RSA::pkic key_synth;
  tancrypt::RSA::pkic key_loaded;
  key_synth.generate_keypair(2048);
  dutils::dbuffer der_synth = key_synth.getPrivDER();
  key_loaded.loadPrivDER(der_synth);
  dutils::dbuffer der_loaded = key_loaded.getPrivDER();
  std::cout << "Generated priv hex:" << std::endl;
  std::cout << dutils::hexStr(der_synth) << std::endl;
  std::cout << "Loaded priv hex:" << std::endl;
  std::cout << dutils::hexStr(der_loaded) << std::endl;

  if (dutils::hexStr(der_synth) != dutils::hexStr(der_loaded)) return 1;
  return 0;
}

int loadPubDER(char*[], int)
{
  tancrypt::RSA::pkic key_synth;
  tancrypt::RSA::pkic key_loaded;
  key_synth.generate_keypair(2048);
  dutils::dbuffer der_synth = key_synth.getPubDER();
  key_loaded.loadPubDER(der_synth);
  dutils::dbuffer der_loaded = key_loaded.getPubDER();
  std::cout << "Generated pub hex:" << std::endl;
  std::cout << dutils::hexStr(der_synth) << std::endl;
  std::cout << "Loaded pub hex:" << std::endl;
  std::cout << dutils::hexStr(der_loaded) << std::endl;

  if (dutils::hexStr(der_synth) != dutils::hexStr(der_loaded)) return 1;
  return 0;
}

int importPrivPEM(char* argv[], int)
{
  tancrypt::RSA::pkic keyc;
  std::cout << "Priv pem: " << argv[2] << std::endl;
  keyc.importPEM(argv[2]);
  std::string content = dutils::hexStr(keyc.getPrivDER());
  std::cout << "Priv hex:" << std::endl;
  std::cout << content << std::endl;
  if (content == "") return 1;

  return 0;
}

int importPubPEM(char* argv[], int)
{
  tancrypt::RSA::pkic keyc;
  keyc.importPEM(argv[2]);
  std::string content = dutils::hexStr(keyc.getPubDER());
  std::cout << "Pub hex:" << std::endl;
  std::cout << content << std::endl;
  if (content == "") return 1;

  return 0;
}

int importBundlePEM(char* argv[], int argc)
{
  if (importPrivPEM(argv, argc) || importPubPEM(argv, argc)) return 1;
  return 0;
}

int getPrivPEM(char* argv[], int)
{
  tancrypt::RSA::pkic key_synth;
  key_synth.generate_keypair(2048);
  std::string synth_pem = key_synth.getPrivPEM();
  std::cout << "Synthesized Priv PEM:" << std::endl;
  std::cout << synth_pem << std::endl;

  tancrypt::RSA::pkic key_imported;
  key_imported.importPEM(argv[2]);
  std::string imported_pem = key_imported.getPrivPEM();
  std::cout << "Synthesized Priv PEM:" << std::endl;
  std::cout << imported_pem << std::endl;

  return 0;
}

int getPubPEM(char* argv[], int)
{
  tancrypt::RSA::pkic key_synth;
  key_synth.generate_keypair(2048);
  std::string synth_pem = key_synth.getPubPEM();
  std::cout << "Synthesized Pub PEM:" << std::endl;
  std::cout << synth_pem << std::endl;

  tancrypt::RSA::pkic key_imported;
  key_imported.importPEM(argv[2]);
  std::string imported_pem = key_imported.getPubPEM();
  std::cout << "Synthesized Pub PEM:" << std::endl;
  std::cout << imported_pem << std::endl;

  return 0;
}

int getBundlePEM(char*[], int)
{
  tancrypt::RSA::pkic key;
  key.generate_keypair(2048);
  std::string bundle_pem = key.getBundlePEM();
  std::cout << "Bundle PEM:" << std::endl;
  std::cout << bundle_pem << std::endl;

  return 0;
}

int loadPrivPEM(char*[], int)
{
  tancrypt::RSA::pkic keyc_synth;
  tancrypt::RSA::pkic keyc_loaded;

  keyc_synth.generate_keypair(2048);
  keyc_loaded.loadPEMStr(keyc_synth.getPrivPEM().c_str());
  std::cout << "Priv synth: " << std::endl;
  std::cout << dutils::hexStr(keyc_synth.getPrivDER()) << std::endl;
  std::cout << "Priv loaded: " << std::endl;
  std::cout << dutils::hexStr(keyc_loaded.getPrivDER()) << std::endl;
  if (dutils::hexStr(keyc_synth.getPrivDER()) != dutils::hexStr(keyc_loaded.getPrivDER())) return 1;
  return 0;
}

int loadPubPEM(char*[], int)
{
  tancrypt::RSA::pkic keyc_synth;
  tancrypt::RSA::pkic keyc_loaded;

  keyc_synth.generate_keypair(2048);
  keyc_loaded.loadPEMStr(keyc_synth.getPubPEM().c_str());
  std::cout << "Pub synth: " << std::endl;
  std::cout << dutils::hexStr(keyc_synth.getPubDER()) << std::endl;
  std::cout << "Pub loaded: " << std::endl;
  std::cout << dutils::hexStr(keyc_loaded.getPubDER()) << std::endl;

  if (dutils::hexStr(keyc_synth.getPubDER()) != dutils::hexStr(keyc_loaded.getPubDER())) return 1;

  return 0;
}

int loadBundlePEM(char*[], int)
{
  tancrypt::RSA::pkic keyc_synth;
  tancrypt::RSA::pkic keyc_loaded;

  keyc_synth.generate_keypair(2048);
  keyc_loaded.loadPEMStr(keyc_synth.getBundlePEM().c_str());
  std::cout << "Pub loaded: " << std::endl;
  std::cout << dutils::hexStr(keyc_loaded.getPubDER()) << std::endl;

  if (dutils::hexStr(keyc_synth.getPrivDER()) != dutils::hexStr(keyc_loaded.getPrivDER())) return 1;
  if (dutils::hexStr(keyc_synth.getPubDER()) != dutils::hexStr(keyc_loaded.getPubDER())) return 1;

  return 0;
}
int exportPrivPEM(char*[], int)
{
  tancrypt::RSA::pkic keyc;
  keyc.generate_keypair(2048);
  keyc.exportPrivPEM("priv_out.pem");

  return 0;
}

int exportPubPEM(char*[], int)
{
  tancrypt::RSA::pkic keyc;
  keyc.generate_keypair(2048);
  keyc.exportPubPEM("pub_out.pem");

  return 0;
}

int exportBundlePEM(char*[], int)
{
  tancrypt::RSA::pkic keyc;
  keyc.generate_keypair(2048);
  keyc.exportBundlePEM("bundle_out.pem");

  return 0;
}

int Encrypt_test(char*[], int)
{
  tancrypt::RSA::pkic key;
  key.generate_keypair(2048);
  dutils::dbuffer payload("Hewwo, I am secret ^.^");
  dutils::dbuffer res = tancrypt::RSA::encrypt(key, payload);
  std::cout << "Original:" << std::endl;
  std::cout << payload.toStr() << std::endl;
  std::cout << "Hex::" << std::endl;
  std::cout << dutils::hexStr(payload) << std::endl;
  std::cout << "Encrypted:" << std::endl;
  std::cout << dutils::hexStr(res) << std::endl;
  if (dutils::hexStr(payload) == dutils::hexStr(res) || res.size() == 0) return 1;

  return 0;
}

int Decrypt_test(char*[], int)
{
  tancrypt::RSA::pkic key;
  key.generate_keypair(2048);
  dutils::dbuffer payload("Hewwo, I am secret ^.^");
  dutils::dbuffer res = tancrypt::RSA::encrypt(key, payload);
  std::cout << "Original:" << std::endl;
  std::cout << payload.toStr() << std::endl;
  std::cout << "Hex:" << std::endl;
  std::cout << dutils::hexStr(payload) << std::endl;
  std::cout << "Encrypted:" << std::endl;
  std::cout << dutils::hexStr(res) << std::endl;
  dutils::dbuffer res_decrypted = tancrypt::RSA::decrypt(key, res);
  std::cout << "Res decrypted hex:" << std::endl;
  std::cout << dutils::hexStr(res_decrypted) << std::endl;
  std::cout << "Res decrypted:" << std::endl;
  std::cout << res_decrypted.toStr() << std::endl;
  if (dutils::hexStr(payload) == dutils::hexStr(res_decrypted)) return 0;

  return 1;
}

int hashTest(char*[], int)
{
  dutils::dbuffer payload("Hewwo, I am secret ^.^");
  dutils::dbuffer hashed_payload = tancrypt::hash(payload, tancrypt::hashAlg::SHA256);
  std::cout << dutils::hexStr(hashed_payload) << std::endl;
  return 0;
}

int signTest(char*[], int)
{
  tancrypt::RSA::pkic key;
  key.generate_keypair(2048);
  dutils::dbuffer payload("Hewwo, I am signed ^.^");
  dutils::dbuffer signature = tancrypt::RSA::sign(key, payload, tancrypt::hashAlg::SHA256);
  std::cout << "Signature hex:" << std::endl;
  std::cout << dutils::hexStr(signature) << std::endl;
  return 0;
}

int verifyTest(char*[], int)
{
  tancrypt::RSA::pkic key;
  key.generate_keypair(2048);
  dutils::dbuffer payload("Hewwo, I am signed ^.^");
  dutils::dbuffer signature = tancrypt::RSA::sign(key, payload, tancrypt::hashAlg::SHA256);
  std::cout << "Signature hex:" << std::endl;
  std::cout << dutils::hexStr(signature) << std::endl;
  bool res = tancrypt::RSA::verify(key, signature, payload, tancrypt::hashAlg::SHA256);

  return res;
}

int AESKEY_init1Test(char*[], int)
{
  using namespace tancrypt;
  dutils::dbuffer my_keydata("Hewwo, I am secret >.<");
  tancrypt::AES::keyc key_variant1(my_keydata, AES::Type::CBC256);

  return 0;
}

int AESKEY_init2Test(char*[], int)
{
  using namespace tancrypt;
  dutils::dbuffer my_keydata("Hewwo, I am secret >.<");
  tancrypt::AES::keyc key_variant2(my_keydata, AES::Type::CBC256, hashAlg::SHA256);

  return 0;
}

int AesEncryptV1(char*[], int)
{

  dutils::dbuffer payload("Hewwo, I am secret >.<");

  using namespace tancrypt;
  dutils::dbuffer my_keydata("Hewwo, I am key ^.^");
  dutils::dbuffer hashed_key = tancrypt::hash(my_keydata, hashAlg::SHA256);
  tancrypt::AES::keyc key_variant1(hashed_key, AES::Type::CBC256);
  dutils::dbuffer enc_buffer = AES::encrypt(key_variant1, payload);

  std::cout << "Original: " << payload.toStr() << std::endl;
  std::cout << "Original(hex): " << dutils::hexStr(payload) << std::endl;
  std::cout << "Encrypted(hex): " << dutils::hexStr(enc_buffer) << std::endl;

  return 0;
}

int AesEncryptV2(char*[], int)
{
  using namespace tancrypt;

  dutils::dbuffer payload("Hewwo, I am secret >.<");

  dutils::dbuffer my_keydata("Hewwo, I am key ^.^");
  tancrypt::AES::keyc key_variant2(my_keydata, AES::Type::CBC256, hashAlg::SHA256);
  dutils::dbuffer enc_buffer = AES::encrypt(key_variant2, payload);

  std::cout << "Original: " << payload.toStr() << std::endl;
  std::cout << "Original(hex): " << dutils::hexStr(payload) << std::endl;
  std::cout << "Encrypted(hex): " << dutils::hexStr(enc_buffer) << std::endl;

  return 0;
}

int AesEncryptwRandomKey(char*[], int)
{

  using namespace tancrypt;

  dutils::dbuffer payload("Hewwo, I am secret >.<");

  AES::keyc random_key = AES::keyc::randomKey(16, AES::Type::CBC256, hashAlg::SHA256);
  dutils::dbuffer enc_buffer = AES::encrypt(random_key, payload);

  std::cout << "Original: " << payload.toStr() << std::endl;
  std::cout << "Original(hex): " << dutils::hexStr(payload) << std::endl;
  std::cout << "Encrypted(hex): " << dutils::hexStr(enc_buffer) << std::endl;

  return 0;
}

int AesDecryptV1(char*[], int)
{
  dutils::dbuffer payload("Hewwo, I am secret >.<");

  using namespace tancrypt;
  dutils::dbuffer my_keydata("Hewwo, I am key ^.^");
  dutils::dbuffer hashed_key = tancrypt::hash(my_keydata, hashAlg::SHA256);
  tancrypt::AES::keyc key_variant1(hashed_key, AES::Type::CBC256);
  dutils::dbuffer enc_buffer = AES::encrypt(key_variant1, payload);

  std::cout << "Original: " << payload.toStr() << std::endl;
  std::cout << "Original(hex): " << dutils::hexStr(payload) << std::endl;
  std::cout << "Encrypted(hex): " << dutils::hexStr(enc_buffer) << std::endl;

  dutils::dbuffer dec_buffer = AES::decrypt(key_variant1, enc_buffer);

  std::cout << "Decrypted(hex): " << dutils::hexStr(dec_buffer) << std::endl;
  std::cout << "Decrypted: " << dec_buffer.data() << std::endl;

  return 0;
}

int AesDecryptV2(char*[], int)
{
  dutils::dbuffer payload("Hewwo, I am secret >.<");

  using namespace tancrypt;
  dutils::dbuffer my_keydata("Hewwo, I am key ^.^");
  tancrypt::AES::keyc key_variant2(my_keydata, AES::Type::CBC256, hashAlg::SHA256);
  dutils::dbuffer enc_buffer = AES::encrypt(key_variant2, payload);

  std::cout << "Original: " << payload.toStr() << std::endl;
  std::cout << "Original(hex): " << dutils::hexStr(payload) << std::endl;
  std::cout << "Encrypted(hex): " << dutils::hexStr(enc_buffer) << std::endl;

  dutils::dbuffer dec_buffer = AES::decrypt(key_variant2, enc_buffer);

  std::cout << "Decrypted(hex): " << dutils::hexStr(dec_buffer) << std::endl;
  std::cout << "Decrypted: " << dec_buffer.data() << std::endl;
  if (dutils::hexStr(dec_buffer) != dutils::hexStr(payload)) return 1;

  return 0;
}

int getNonce_test(char*[], int)
{
  dutils::dbuffer payload("Hewwo, I am secret >.<");

  using namespace tancrypt;
  dutils::dbuffer my_keydata("Hewwo, I am key ^.^");
  dutils::dbuffer hashed_key = tancrypt::hash(my_keydata, hashAlg::SHA256);
  tancrypt::AES::keyc key_variant1(hashed_key, AES::Type::CBC256);
  dutils::dbuffer enc_buffer = AES::encrypt(key_variant1, payload);

  dutils::dbuffer nonce_out = tancrypt::AES::getNonce(enc_buffer, AES::Type::CBC256);
  std::cout << dutils::hexStr(nonce_out) << std::endl;

  return 0;
}

int debugPass(char* argv[], int argc)
{
  std::cout << "Arg pass: ";
  for (int i = 0; i < argc; i++)
  {
    std::cout << argv[i];
  }
  std::cout << std::endl;

  return 0;
}

std::map<std::string, std::function<int(char* argv[], int argc)>> handler = {
  { "--pkicInit", &pkicInit },
  { "--pairGen", &keypairGen },
  { "--pairRegen", &keypairRegen },
  { "--pairMultigen", &keypairMultigen },
  { "--getPrivDER", &getPrivDER },
  { "--getPubDER", &getPubDER },
  { "--loadPrivDER", &loadPrivDER },
  { "--loadPubDER", &loadPubDER },
  { "--getPrivPEM", &getPrivPEM },
  { "--getPubPEM", &getPubPEM },
  { "--getBits", &getBits },
  { "--loadPrivPEM", &loadPrivPEM },
  { "--loadPubPEM", &loadPubPEM },
  { "--loadBundlePEM", &loadBundlePEM },
  { "--getBundlePEM", &getBundlePEM },
  { "--importPrivPEM", &importPrivPEM },
  { "--importPubPEM", &importPubPEM },
  { "--importBundlePEM", &importBundlePEM },
  { "--exportPrivPEM", &exportPrivPEM },
  { "--exportPubPEM", &exportPubPEM },
  { "--exportBundlePEM", &exportBundlePEM },
  { "--encrypt", &Encrypt_test },
  { "--decrypt", &Decrypt_test },
  { "--hash", &hashTest },
  { "--sign", &signTest },
  { "--verify", &verifyTest },
  { "--aesKeyInit1", &AESKEY_init1Test },
  { "--aesKeyInit2", &AESKEY_init2Test },
  { "--aesRandomKey", &aesRandomKey },
  { "--aesEncryptV1", &AesEncryptV1 },
  { "--aesEncryptV2", &AesEncryptV2 },
  { "--aesDecryptV1", &AesDecryptV1 },
  { "--aesDecryptV2", &AesDecryptV2 },
  { "--aesEncryptwRandomKey", &AesEncryptwRandomKey },
  { "--getNonce", &getNonce_test },
  { "--debugTest", &debugPass }
};

void printUsage(std::string bin_name)
{
  std::cout << " " << std::endl;
  std::cout << "usage: " << bin_name << " [option]" << std::endl;
  std::cout << "Available options: [";
  for (auto v_pair : handler)
  {
    std::cout << "  " << v_pair.first;
  }
  std::cout << "]" << std::endl;
}

int main(int argc, char* argv[])
{
  if ((argc - 1) < 1)
  {
    std::cout << "Invalid usage." << std::endl;
    printUsage("tancrypt-test");
    return 1;
  }

  if (handler.count(argv[1]) != 1)
  {
    std::cout << "Invalid option: " << argv[1] << std::endl;
    printUsage("tancrypt-test");
    return 1;
  }

  return handler[argv[1]](argv, argc);
}
