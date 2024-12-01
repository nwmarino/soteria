//>==- container.cpp ------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#include <cstdint>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string>
#include <vector>

#include "../../include/cli/cli.h"
#include "../../include/container/container.h"
#include "../../include/encryption/aes.h"

using namespace soteria;

Container::Container(const std::string &path) 
    : path(path), name(path.substr(path.find_last_of('/') + 1)) {
  container.open(this->path, std::ios::binary | std::ios::in | std::ios::out);
  if (!container)
    cli::fatal("unable to open container: " + name);
}

Container::Container(const std::string &name, 
                     const std::string &path,
                     std::size_t size) : name(name), path(path) {
  container.open(
    this->path, 
    std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc
  );

  if (!container)
    cli::fatal("unable to create container: " + name);

  std::vector<unsigned char> empty_data(size, 0);
  container.write(reinterpret_cast<const char *>(empty_data.data()), size);
}

Container::~Container() { container.close(); }

Container *Container::create(const std::string &path, std::size_t size) 
{ return new Container("container", path, size); }

Container *Container::open(const std::string &path) 
{ return new Container(path); }

void Container::store_file(const std::string &in_path,
                           const std::vector<unsigned char> &key) {
  // Generate a new IV for the file.
  const std::size_t iv_size = AES_BLOCK_SIZE;
  std::vector<unsigned char> iv(iv_size);
  if (!RAND_bytes(iv.data(), iv_size))
    cli::fatal("failed to generate IV for file: " + in_path);


  // Open the input file.
  std::ifstream in_file(in_path, std::ios::binary);
  if (!in_file)
    cli::fatal("unable to open file: " + in_path);


  // Get the file size.
  in_file.seekg(0, std::ios::end);
  std::uint64_t file_size = in_file.tellg();
  in_file.seekg(0, std::ios::beg);


  // Write file metadata.
  std::uint32_t filename_len = in_path.size();
  container.write(reinterpret_cast<const char *>(&filename_len), sizeof(filename_len));
  container.write(in_path.data(), filename_len);
  container.write(reinterpret_cast<const char *>(iv.data()), iv_size);

  // Encrypt file contents.
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    cli::fatal("failed to create EVP context for file: " + in_path);

  if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
      key.data(), iv.data())) {
    cli::fatal("failed to initialize encryption for file: " + in_path);
  }

  // 4096 -> file_size
  std::vector<unsigned char> buffer(4096);
  std::vector<unsigned char> enc_buffer(4096 + AES_BLOCK_SIZE);
  int len = 0;

  std::uint64_t enc_size = 0;
  std::streampos size_pos = container.tellp();
  container.write(reinterpret_cast<const char*>(&enc_size), sizeof(enc_size));

  while (in_file) {
    in_file.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
    std::streamsize bytes_read = in_file.gcount();

    if (bytes_read > 0) {
      if (!EVP_EncryptUpdate(ctx, enc_buffer.data(), &len, 
          buffer.data(), bytes_read)) {
        cli::fatal("failed to encrypt data for file: " + in_path);
      }

      container.write(reinterpret_cast<const char *>(enc_buffer.data()), len);
      enc_size += len;
    }
  }

  if (!EVP_EncryptFinal_ex(ctx, enc_buffer.data(), &len))
    cli::fatal("failed to finalize encryption for file: " + in_path);

  container.write(reinterpret_cast<const char *>(enc_buffer.data()), len);
  enc_size += len;

  std::streampos current_pos = container.tellp();
  container.seekp(size_pos, std::ios::beg);
  container.write(reinterpret_cast<const char*>(&enc_size), sizeof(enc_size));
  container.seekp(current_pos, std::ios::beg);

  EVP_CIPHER_CTX_free(ctx);
}

void Container::load_file(const std::string &out_path,
                          const std::vector<unsigned char> &key) {
  const std::size_t iv_size = AES_BLOCK_SIZE;
  while (this->container) {
    // Read metadata.
    std::uint32_t filename_len = 0;
    container.read(reinterpret_cast<char *>(&filename_len), sizeof(filename_len));
    if (!this->container) 
      break;

    if (filename_len == 0 || filename_len > 1024)
      cli::fatal("invalid filename length in container: " + out_path);

    std::string stored_filename(filename_len, '\0');
    container.read(&stored_filename[0], filename_len);

    std::vector<unsigned char> iv(iv_size);
    container.read(reinterpret_cast<char *>(iv.data()), iv_size);

    std::uint64_t enc_size = 0;
    container.read(reinterpret_cast<char *>(&enc_size), sizeof(enc_size));

    // Read encrypted file content.
    std::vector<unsigned char> encrypted_data(enc_size);
    container.read(reinterpret_cast<char *>(encrypted_data.data()), enc_size);
    if (!container) 
      cli::fatal("failed to read encrypted data for file: " + out_path);

    if (stored_filename == out_path) {
      // Found the matching file, decrypt it.
      EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
      if (!ctx) 
        cli::fatal("failed to create EVP context for file: " + out_path);

      if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
          key.data(), iv.data())) {
        cli::fatal("failed to initialize decryption for file: " + out_path);
      }

      std::vector<unsigned char> decrypted_data(enc_size);
      int len = 0;
      int total_len = 0;

      if (!EVP_DecryptUpdate(ctx, decrypted_data.data(), &len, 
          encrypted_data.data(), encrypted_data.size())) {
        cli::fatal("failed to decrypt data for file: " + out_path);
      }
      total_len += len;

      if (!EVP_DecryptFinal_ex(ctx, decrypted_data.data() + total_len,
          &len)) {
        cli::fatal("failed to finalize decryption for file: " + out_path);
      }
      total_len += len;

      decrypted_data.resize(total_len);

      // Write the decrypted data to the output file.
      std::ofstream out_file(out_path, std::ios::binary);
      if (!out_file) 
        cli::fatal("unable to open output file: " + out_path);
    
      out_file.write(reinterpret_cast<const char*>(decrypted_data.data()), 
          decrypted_data.size());

      EVP_CIPHER_CTX_free(ctx);
      return;
    }
  }

  cli::fatal("file not found in container: " + out_path);
}
