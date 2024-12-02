//>==- container.cpp ------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "boost/filesystem.hpp"
#include "openssl/aes.h"
#include "openssl/rand.h"

#include "../../include/cli/cli.h"
#include "../../include/core/container.h"
#include "../../include/core/fat.h"
#include "../../include/utils/compression.h"
#include "../../include/utils/encryption.h"
#include "../../include/utils/file.h"

namespace fs = boost::filesystem;

using namespace soteria;

Container::Container(const std::string &path,
                     const std::string &pass) 
    : path(path), name(path.substr(path.find_last_of('/') + 1)) {
  container.open(
    this->path,
    std::ios::binary | std::ios::in | std::ios::out
  );

  if (!fs::exists(path))
    cli::fatal("unable to open container: " + name);

  // Read the salt and hashed password from the container.
  std::size_t salt_len, hash_len;
  container.read(reinterpret_cast<char *>(&salt_len), sizeof(salt_len));
  std::vector<unsigned char> salt(salt_len);
  container.read(reinterpret_cast<char *>(salt.data()), salt_len);
  container.read(reinterpret_cast<char *>(&hash_len), sizeof(hash_len));
  std::vector<unsigned char> stored_hash(hash_len);
  container.read(reinterpret_cast<char *>(stored_hash.data()), hash_len);

  // Check if the password matches the stored hash.
  if (!match_password(
      std::string(stored_hash.begin(), stored_hash.end()),
      pass,
      salt
    ))
    cli::fatal("incorrect password for container: " + name);

  // Clear the stored hash from memory.
  std::fill(stored_hash.begin(), stored_hash.end(), 0);

  // Read the FAT from the container.
  read_fat();
}

Container::Container(const std::string &name, 
                     const std::string &path,
                     const std::string &pass,
                     std::size_t size) : name(name), path(path) {
  container.open(
    this->path,
    std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc
  );

  if (!fs::exists(path))
    cli::fatal("unable to create container: " + name);

  // Write empty data to the container.
  std::vector<unsigned char> empty_data(size, 0);
  container.write(reinterpret_cast<const char *>(empty_data.data()), size);

  // Generate a random salt for the password.
  std::vector<unsigned char> salt(16);
  if (!RAND_bytes(salt.data(), salt.size())) {
    fs::remove(path); // Remove the container.
    cli::fatal("failed to generate salt on container creation");
  }

  // Hash the password.
  std::vector<unsigned char> hashed_password = hash_password(pass, salt);
  std::size_t salt_len = salt.size();
  std::size_t hash_len = hashed_password.size();

  // Write the salt and hashed password to the container.
  container.write(
    reinterpret_cast<const char *>(&salt_len), 
    sizeof(salt_len)
  );
  container.write(
    reinterpret_cast<const char *>(salt.data()), 
    salt.size()
  );
  container.write(
    reinterpret_cast<const char *>(&hash_len), 
    sizeof(hash_len)
  );
  container.write(
    reinterpret_cast<const char *>(hashed_password.data()), 
    hashed_password.size()
  );

  // Clear the hashed password from memory.
  std::fill(hashed_password.begin(), hashed_password.end(), 0);

  // Write the FAT to the container.
  write_fat();
}

Container::~Container() { container.close(); }

Container *Container::create(const std::string &path,
                             const std::string &pass,
                             std::size_t size) { 
  return new Container(
    path.substr(path.find_last_of('/') + 1), 
    path,
    pass,
    size
  );
}

Container *Container::open(const std::string &path, const std::string &pass)
{ return new Container(path, pass); }

void Container::store_file(const std::string &in_path, 
                           const std::string &password) {
  std::vector<unsigned char> enc_key = load_key(password);
  read_fat();

  // Find an existing entry in the FAT to potentially overwrite it.
  auto it = std::find_if(
    fat.begin(), 
    fat.end(),
    [&in_path](const FATEntry &entry) -> bool {
      return entry.filename == in_path;
    }
  );

  // Collect file data and compress it.
  std::vector<unsigned char> file_data = gen_read_file(in_path);
  std::vector<unsigned char> compressed_data = compress(file_data);
  std::string checksum = generate_sha256(file_data);

  // Encrypt compressed file data.
  std::vector<unsigned char> iv = generate_rand(16);
  std::vector<unsigned char> enc_data = aes_encrypt(compressed_data, enc_key, iv);

  // Update the FAT entry for this file.
  FATEntry entry;
  if (it != fat.end()) {
    // Overwrite the existing entry, if it existed.
    entry = *it;
  } else {
    // Create a new entry if one didn't exist.
    entry.filename = in_path;
    fat.push_back(entry);
  }

  // Update FAT metadata.
  entry.checksum = checksum;
  entry.size = file_data.size();
  entry.compressed_size = compressed_data.size();
  entry.enc_size = enc_data.size();
  entry.offset = end_offset();
  entry.iv = iv;

  // Write encrypted data to the container.
  container.seekp(entry.offset);
  container.write(
    reinterpret_cast<const char *>(iv. data()), 
    iv.size()
  );
  container.write(
    reinterpret_cast<const char *>(enc_data.data()), 
    enc_data.size()
  );

  // Update the FAT.
  write_fat();
}

void Container::load_file(const std::string &out_path, 
                          const std::string &password) {
  std::vector<unsigned char> enc_key = load_key(password);
  read_fat();

  // Locate the file in the FAT.
  auto it = std::find_if(
    fat.begin(),
    fat.end(),
    [&out_path](const FATEntry &entry) -> bool { 
      return entry.filename == out_path; 
    }
  );

  if (it == fat.end())
    cli::fatal("unresolved file in container: " + out_path);

  const FATEntry entry = *it;

  // Go to the existing file offset for reading.
  container.seekg(entry.offset);
}

void Container::write_fat() {
  for (const FATEntry &entry : this->fat) {
    uint32_t name_len = entry.filename.size();
    container.write(reinterpret_cast<const char *>(&name_len), sizeof(name_len));
    container.write(entry.filename.c_str(), name_len);

    container.write(
      reinterpret_cast<const char *>(&entry.size), 
      sizeof(entry.size)
    );
    container.write(
      reinterpret_cast<const char *>(&entry.offset), 
      sizeof(entry.offset)
    );

    uint32_t checksum_len = entry.checksum.size();
    container.write(reinterpret_cast<const char *>(&checksum_len), sizeof(checksum_len));
    container.write(entry.checksum.c_str(), checksum_len);
  }
}

void Container::read_fat() {
  while (this->container) {
    FATEntry entry;
    uint32_t name_len;

    container.read(reinterpret_cast<char *>(&name_len), sizeof(name_len));
    if (!this->container)
      break;

    std::vector<char> name_buf(name_len);
    container.read(name_buf.data(), name_len);
    entry.filename = std::string(name_buf.begin(), name_buf.end());

    container.read(reinterpret_cast<char *>(&entry.size), sizeof(entry.size));
    container.read(reinterpret_cast<char *>(&entry.offset), sizeof(entry.offset));

    uint32_t checksum_len;
    container.read(reinterpret_cast<char *>(&checksum_len), sizeof(checksum_len));
    std::vector<char> checksum_buf(checksum_len);
    container.read(checksum_buf.data(), checksum_len);
    entry.checksum = std::string(checksum_buf.begin(), checksum_buf.end());

    fat.push_back(entry);
  }
}

void Container::store_key(const std::vector<unsigned char> &key, 
                          const std::string &password) {
  std::vector<unsigned char> salt(16);
  if (!RAND_bytes(salt.data(), salt.size()))
    cli::fatal("failed to generate salt for KEK storage");

  // Derive the KEK from the password.
  std::vector<unsigned char> kek = hash_password(password, salt);

  // Encrypt the encryption key with the kek.
  std::vector<unsigned char> iv(16);
  if (!RAND_bytes(iv.data(), iv.size()))
    cli::fatal("failed to generate IV for KEK storage");
  std::vector<unsigned char> encrypted_key = aes_encrypt(key, kek, iv);

  std::size_t salt_len = salt.size();
  std::size_t key_len = encrypted_key.size();

  // Write the salt, IV, and encrypted key to the container.
  container.write(
    reinterpret_cast<const char *>(&salt_len), 
    sizeof(salt_len)
  );
  container.write(
    reinterpret_cast<const char *>(salt.data()), 
    salt.size()
  );
  container.write(
    reinterpret_cast<const char *>(iv.data()), 
    iv.size()
  );
  container.write(
    reinterpret_cast<const char *>(&key_len), 
    sizeof(key_len)
  );
  container.write(
    reinterpret_cast<const char *>(encrypted_key.data()), 
    key_len
  );
}

std::vector<unsigned char> Container::load_key(const std::string &password) {
  // Read the salt.
  std::size_t salt_len;
  container.read(reinterpret_cast<char *>(&salt_len), sizeof(salt_len));
  std::vector<unsigned char> salt(salt_len);
  container.read(reinterpret_cast<char *>(salt.data()), salt_len);

  // Read the IV and encryption key.
  std::vector<unsigned char> iv(16);
  container.read(reinterpret_cast<char *>(iv.data()), iv.size());

  std::size_t key_len;
  container.read(reinterpret_cast<char *>(&key_len), sizeof(key_len));
  std::vector<unsigned char> encrypted_key(key_len);
  container.read(reinterpret_cast<char *>(encrypted_key.data()), key_len);

  // Derive the KEK and decrypt the encryption key.
  std::vector<unsigned char> kek = hash_password(password, salt);
  return aes_decrypt(encrypted_key, kek, iv);
}

void Container::change_master(const std::string &old_pass, 
                              const std::string &new_pass) {
  // Retrieve the current encryption key.
  std::vector<unsigned char> encryption_key = load_key(old_pass);

  // Store the encryption key with the new password.
  store_key(encryption_key, new_pass);
}

std::size_t Container::end_offset() const {
  container.seekp(0, std::ios::end);
  return container.tellp();
}