//>==- aes.cpp ------------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "openssl/aes.h"
#include "openssl/rand.h"
#include "openssl/evp.h"

#include "../../include/encryption/aes.h"
#include "../../include/cli/cli.h"

using namespace soteria;

void soteria::generate_key_iv(std::vector<unsigned char> &key, 
                            std::vector<unsigned char> &iv,
                            std::size_t key_len, std::size_t iv_len) {
  key.resize(key_len);
  iv.resize(iv_len);

  if (!RAND_bytes(key.data(), key_len) 
      || !RAND_bytes(iv.data(), iv_len)) {
    cli::fatal("failed to generate key");
  }
}

void soteria::aes_encrypt_file(const std::string &in_path, 
                               const std::string &out_path,
                               const std::vector<unsigned char> &key,
                               const std::vector<unsigned char> &iv) {
  const std::size_t chunk_size = 4096;
  std::ifstream in_file(in_path, std::ios::binary);
  std::ofstream out_file(out_path, std::ios::binary);

  // Check that the I/o files could be opened.
  if (!in_file)
    cli::fatal("unable to open input file: " + in_path);

  if (!out_file)
    cli::fatal("unable to open output file: " + out_path);

  // Begin the output file with the IV.
  out_file.write(reinterpret_cast<const char *>(iv.data()), iv.size());

  std::vector<unsigned char> buffer(chunk_size);
  std::vector<unsigned char> enc_buffer(chunk_size + AES_BLOCK_SIZE);
  int len = 0;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    cli::fatal("failed to create EVP context");

  if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
      key.data(), iv.data())) {
    cli::fatal("failed to initialize encryption");
  }

  while (in_file) {
    in_file.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
    std::streamsize bytes_read = in_file.gcount();

    if (bytes_read > 0) {
      if (!EVP_EncryptUpdate(ctx, enc_buffer.data(), &len,
          buffer.data(), bytes_read)) {
        cli::fatal("failed to encrypt data");
      }

      out_file.write(reinterpret_cast<const char *>(enc_buffer.data()), len);
    }
  }

  if (!EVP_EncryptFinal_ex(ctx, enc_buffer.data(), &len))
    cli::fatal("failed to finalize encryption");

  out_file.write(reinterpret_cast<const char *>(enc_buffer.data()), len);
  EVP_CIPHER_CTX_free(ctx);
}
