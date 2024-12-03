//>==- container.cpp ------------------------------------------------------==<//
//
// { MASTER }
// [0 : 16] -> MASTER SALT (16-byte)
// [16 : 48] -> MASTER HASH (32-byte)
//
// { FAT }
// [48 : 52] -> FAT ENTRY COUNT (4-byte)
// [52 : ?] -> FILE 1 METADATA
//   [0 : 4] -> FILE NAME LENGTH (4-byte)
//   [4 : 4 + FILE NAME LENGTH] -> FILE NAME (variable)
//   [4 + FILE NAME LENGTH : 12 + FILE NAME LENGTH] -> ORIGINAL FILE SIZE (8-byte)
//   [12 + FILE NAME LENGTH ]



// [(8 + salt_size + hash_size) - (FAT entry count offset)] -> FAT entry count (4 bytes)
// [(FAT entry count offset) + 4] -> File 1 metadata:
//   - File name length (4 bytes)
//   - File name (variable size)
//   - Original file size (8 bytes)
//   - Last modified timestamp (8 bytes)
//   - Encrypted data offset (8 bytes)
// [(FAT entry count offset) + 4 + (size of all file metadata)] -> File 2 metadata, etc.
// 
// [Encrypted Data]
// [After FAT] -> Encrypted data for each file (variable size)
// 
// [Encryption Key]
// [After encrypted data] -> Encryption key (variable size)
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
#include "openssl/sha.h"

#include "../../include/cli/cli.h"
#include "../../include/core/container.h"
#include "../../include/core/fat.h"
#include "../../include/utils/compression.h"
#include "../../include/utils/encryption.h"
#include "../../include/utils/file.h"
#include <iomanip>

namespace fs = boost::filesystem;

using namespace soteria;

constexpr std::size_t WIDTH_SALT = 16;
constexpr std::size_t WIDTH_HASH = 32;

constexpr std::size_t OFFSET_MASTER_SALT = 0;
constexpr std::size_t OFFSET_MASTER_HASH = OFFSET_MASTER_SALT + WIDTH_SALT;
constexpr std::size_t OFFSET_FAT = OFFSET_MASTER_HASH + WIDTH_HASH;

/// Open-constructor.
Container::Container(const std::string &path,
                     const std::string &pass) 
    : path(path), name(path.substr(path.find_last_of('/') + 1)) {
  if (!fs::exists(this->path)) {
    cli::fatal("container does not exist: " + name);
  }

  container.open(
    this->path,
    std::ios::binary | std::ios::in | std::ios::out
  );

  if (!container || !container.is_open())
    cli::fatal("failed to open container: " + name);

  load_master();
  if (!match_password(pass, this->master, this->salt)) {
    container.close();
    std::fill(salt.begin(), salt.end(), 0);
    std::fill(master.begin(), master.end(), 0);
    cli::fatal("incorrect password for container: " + name);
  }
}

/// Create-constructor.
Container::Container(const std::string &name, 
                     const std::string &path,
                     const std::string &pass,
                     std::size_t size) : name(name), path(path) {
  container.open(
    this->path,
    std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc
  );

  if (!container.is_open()) {
    cli::fatal("failed to create container: " + name);
  }

  // Hash the new master and store it to the container.
  this->salt = generate_rand(WIDTH_SALT);
  this->master = hash_password(pass, salt);
  store_master();

  // Write the remaining initial space as empty.
  std::vector<unsigned char> empty_space(size - container.tellp(), 0);
  container.write(
    reinterpret_cast<const char *>(empty_space.data()), 
    empty_space.size()
  );

  store_fat();
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

/// Writes container::master to the container.
///
/// This function writes the master password has with a new salt to the 
/// container on the following byte layout:
///
/// { [salt : 16][hash : 32] ... }
///
/// This function wipes the stored salt, hash from container memory.
void Container::store_master() {
  // Clear the container positioning for writing.
  container.clear();
  container.seekp(0, std::ios::beg);

  // Write the salt.
  assert(container.tellp() == OFFSET_MASTER_SALT);
  if (!container.write(
    reinterpret_cast<char *>(salt.data()), 
    WIDTH_SALT
  )) {
    cli::fatal("failed to write salt to container: " + name);
  }

  // Write the password hash.
  assert(container.tellp() == OFFSET_MASTER_HASH);
  if (!container.write(
    reinterpret_cast<char *>(master.data()), 
    WIDTH_HASH
  )) {
    cli::fatal("failed to write hash to container: " + name);
  }

  // Clear the salt, hash from memory.
  std::fill(salt.begin(), salt.end(), 0);
  std::fill(master.begin(), master.end(), 0);
}

/// Reads the stored container salt and hash to container::master.
///
/// The function reads on the following byte layout:
///
/// { [salt : 16][hash : 32] ... }
///
void Container::load_master() {
  // Clear the container positioning for reading.
  container.clear();
  container.seekg(0, std::ios::beg);

  // Read the stored salt.
  std::vector<unsigned char> tmp_salt(WIDTH_SALT);
  assert(container.tellg() == OFFSET_MASTER_SALT);
  if (!container.read(
    reinterpret_cast<char *>(tmp_salt.data()),
    tmp_salt.size()
  )) {
    cli::fatal("(load_master): failed to read salt from container: " + name);
  }

  // Read the stored hash.
  std::vector<unsigned char> tmp_hash(WIDTH_HASH);
  container.seekg(16, std::ios::beg);
  assert(container.tellg() == OFFSET_MASTER_HASH);
  if (!container.read(
    reinterpret_cast<char *>(tmp_hash.data()), 
    tmp_hash.size()
  )) {
    cli::fatal("failed to read hash from container: " + name);
  }

  // Assign the temporary salt, hash and clear them from memory.
  this->salt = tmp_salt;
  this->master = tmp_hash;
  std::fill(tmp_salt.begin(), tmp_salt.end(), 0);
  std::fill(tmp_hash.begin(), tmp_hash.end(), 0);
}

/// Stores the current state of the FAT to the container.
void Container::store_fat() {
  container.clear();
  container.seekp(OFFSET_FAT, std::ios::beg);
  if (!container)
    cli::fatal("(store_fat): failed to write FAT to container: " + name);

  // Attempt to write the number of entries in the FAT.
  std::uint32_t entries = this->fat.size();
  if (!container.write(
    reinterpret_cast<const char *>(&entries), 
    sizeof(std::uint32_t)
  )) {
    cli::fatal("(store_fat): failed to write FAT entry count to container: " + name);
  }

  // Serialize each entry.
  for (const FATEntry &entry : this->fat) {
    if (!container.write(
      reinterpret_cast<const char *>(&entry), 
      sizeof(FATEntry)
    )) {
      cli::fatal("(store_fat): failed to write FAT entry to container: " + name);
    }
  }

  // Flush the container to ensure the FAT is written.
  container.flush();
  if (!container)
    cli::fatal("(store_fat): failed to flush container: " + name);
}

void Container::load_fat() {
  // Attempt to seek to the FAT offset.
  container.clear();
  container.seekp(OFFSET_FAT, std::ios::beg);
  if (!container)
    cli::fatal("(load_fat): failed to seek to FAT offset: " + name);

  // Read the number of entires in the FAT.
  std::uint32_t entries;
  if (!container.read(
    reinterpret_cast<char *>(&entries), 
    sizeof(std::uint32_t)
  )) {
    cli::fatal("(load_fat): failed to read FAT entries from container: " + name);
  }

  // Read all entries from the FAT.
  std::vector<FATEntry> tmp_fat = {};
  for (unsigned idx = 0; idx < entries; ++idx) {
    FATEntry entry;
    if (!container.read(
      reinterpret_cast<char *>(&entry), 
      sizeof(FATEntry)
    )) {
      cli::fatal("(load_fat): failed to read FAT entry from container: " + name);
    }

    tmp_fat.push_back(entry);
  }

  this->fat = tmp_fat;
}

void Container::list(const std::string &path) {
  load_fat();

  // Attempt to open the dump file.
  std::ofstream output(path);
  if (!output || !output.is_open())
    cli::fatal("(list): failed to open output file: " + path);

  // Write a formatted header.
  output << std::left << std::setw(30) << "Filename"
         << std::setw(15) << "Original Size"
         << std::setw(25) << "Last Modified" << std::endl;
  output << std::string(58, '-') << std::endl;

  for (const FATEntry &entry : fat) {
    std::tm *time_info = std::gmtime(&entry.last_modified);
    if (!time_info)
      cli::fatal("(list): failed to convert timestamp to string");

    std::ostringstream timestamp_str;
    timestamp_str << std::put_time(time_info, "%Y-%m-%d %H:%M:%S");

    // Write metadata to the text file
    output << std::setw(30) << entry.filename
           << std::setw(15) << entry.original_size
           << std::setw(25) << timestamp_str.str() << std::endl;
  }

  output.close();
}

/*
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
    reinterpret_cast<const char *>(iv.data()), 
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

*/