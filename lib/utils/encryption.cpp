//>==- encryption.cpp -----------------------------------------------------==<//
//
// The following source implements encryption and hashing fuctions declared
// in the header file encryption.h.
//
//>==----------------------------------------------------------------------==<//

#include "boost/filesystem/operations.hpp"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include "openssl/sha.h"

#include "cli/cli.h"
#include "utils/encryption.h"
#include "utils/file.h"
#include <iostream>

namespace fs = boost::filesystem;

using namespace soteria;

std::vector<unsigned char> soteria::generate_rand(const std::size_t len) {
  std::vector<unsigned char> rand(len);
  if (!RAND_bytes(rand.data(), rand.size()))
    cli::fatal("[generate_rand] failed to generate random bytes");

  return rand;
}

std::array<unsigned char, 16> soteria::generate_iv() {
  std::array<unsigned char, 16> iv;
  if (!RAND_bytes(iv.data(), iv.size()))
    cli::fatal("[generate_iv] failed to generate IV");

  return iv;
}

std::array<unsigned char, 32> soteria::generate_key() {
  std::array<unsigned char, 32> key;
  if (!RAND_bytes(key.data(), key.size()))
    cli::fatal("[generate_key] failed to generate random key");

  return key;
}

std::array<unsigned char, 32> soteria::compute_checksum(const std::string &path) {
  if (!fs::exists(path))
    cli::fatal("[compute_checksum] file does not exist: " + path);

  std::vector<unsigned char> data = gen_read_file(path);
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(data.data(), data.size(), hash);

  // Copy the hash to a fixed-size array.
  std::array<unsigned char, 32> checksum;
  std::copy(
    hash, 
    hash + SHA256_DIGEST_LENGTH, 
    checksum.begin()
  );

  return checksum;
}

std::array<unsigned char, 32> 
soteria::compute_checksum(const std::vector<unsigned char> &data) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(data.data(), data.size(), hash);

  // Copy the hash to a fixed-size array.
  std::array<unsigned char, 32> checksum;
  std::copy(
    hash, 
    hash + SHA256_DIGEST_LENGTH, 
    checksum.begin()
  );

  return checksum;
}

std::vector<unsigned char>
soteria::aes_encrypt(const std::vector<unsigned char> &data,
                     const std::array<unsigned char, 32> &key,
                     const std::array<unsigned char, 16> &iv) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    cli::fatal("[aes_encrypt] context creation failed");

  // Attempt to initialize encryption.
  if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
      key.data(), iv.data())) {
    EVP_CIPHER_CTX_free(ctx);
    cli::fatal("[aes_encrypt] initialization failed");
  }

  // Initialize ciphertext buffer to read into.
  int len = 0;
  int encrypted_len = 0;
  std::vector<unsigned char> encrypted_data(data.size() + EVP_MAX_BLOCK_LENGTH);

  // Attempt to encrypt data.
  if (!EVP_EncryptUpdate(ctx, encrypted_data.data(), &len, 
      data.data(), data.size())) {
    EVP_CIPHER_CTX_free(ctx);
    cli::fatal("[aes_encrypt] update failed");
  }
  encrypted_len = len;

  // Attempt to finalize encryption.
  if (!EVP_EncryptFinal_ex(ctx, encrypted_data.data() + len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    cli::fatal("[aes_encrypt] finalization failed");
  }
  encrypted_len += len;

  // Resize ciphertext buffer to actual read size.
  encrypted_data.resize(encrypted_len);
  EVP_CIPHER_CTX_free(ctx);
  return encrypted_data;
}

std::vector<unsigned char> 
soteria::aes_decrypt(const std::vector<unsigned char> &data,
                     const std::array<unsigned char, 32> &key,
                     const std::array<unsigned char, 16> &iv) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    cli::fatal("[aes_decrypt] context creation failed");

  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
      key.data(), iv.data())) {
    EVP_CIPHER_CTX_free(ctx);
    cli::fatal("[aes_decrypt] initialization failed");
  }

  /// Initialize plaintext buffer to read into.
  int len = 0;
  int decrypted_len = 0;
  std::vector<unsigned char> decrypted_data(data.size() + EVP_MAX_BLOCK_LENGTH);

  // Attempt to decrypt data.
  if (!EVP_DecryptUpdate(ctx, decrypted_data.data(), &len, 
      data.data(), data.size())) {
    EVP_CIPHER_CTX_free(ctx);
    cli::fatal("[aes_decrypt] update failed");
  }
  decrypted_len = len;

  // Attempt to finalize decryption.
  if (!EVP_DecryptFinal_ex(ctx, decrypted_data.data() + len, &len)) {
    unsigned long err_code = ERR_get_error();
    std::cerr << "Decryption failed with error code: " << err_code << std::endl;
    // You can also print out a human-readable error message
    char err_buff[120];
    ERR_error_string_n(err_code, err_buff, sizeof(err_buff));
    std::cerr << "OpenSSL error: " << err_buff << std::endl;
    EVP_CIPHER_CTX_free(ctx);
    cli::fatal("[aes_decrypt] finalization failed");
  }
  decrypted_len += len;

  // Resize plaintext buffer to actual read size.
  decrypted_data.resize(decrypted_len);
  EVP_CIPHER_CTX_free(ctx);
  return decrypted_data;
}

std::vector<unsigned char> 
soteria::hash_password(const std::string &data,
                       const std::vector<unsigned char> &salt,
                       const unsigned int iterations,
                       const unsigned int len) {
  std::vector<unsigned char> hash(len);
  if (!PKCS5_PBKDF2_HMAC(data.c_str(), data.size(), salt.data(), salt.size(),
      iterations, EVP_sha256(), len, hash.data())) {
    cli::fatal("[hash_password] failed to hash");
  }

  return hash;
}

bool soteria::match_password(const std::string &password,
                             const std::vector<unsigned char> &hash,
                             const std::vector<unsigned char> &salt) {
  std::vector<unsigned char> hashed_password = hash_password(password, salt);

  // Compare the stored password with the input password.
  return std::string(hash.begin(), hash.end()) == std::string(
    hashed_password.begin(), 
    hashed_password.end()
  );
}
