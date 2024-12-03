//>==- container.cpp ------------------------------------------------------==<//
//
// { MASTER }
// [0 : 16] -> MASTER SALT (16-byte)
// [16 : 48] -> MASTER HASH (32-byte)
//
// { FAT }
// [48 : 52] -> FAT ENTRY COUNT (4-byte)
// [52 : FAT ENTRIES * 40] -> FAT ENTRIES (40-byte ea.)
//
//>==----------------------------------------------------------------------==<//

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "boost/filesystem.hpp"
#include "boost/iostreams/filtering_stream.hpp"
#include "boost/iostreams/filter/zlib.hpp"

#include "openssl/aes.h"
#include "openssl/rand.h"
#include "openssl/sha.h"

#include "../../include/cli/cli.h"
#include "../../include/core/container.h"
#include "../../include/core/fat.h"
#include "../../include/utils/compression.h"
#include "../../include/utils/encryption.h"
#include "../../include/utils/file.h"

namespace fs = boost::filesystem;
namespace ios = boost::iostreams;

using namespace soteria;

constexpr std::size_t PBKDF2_ITERATIONS = 100000;

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

  // Derive the encryption key.
  std::array<unsigned char, 32> derived_tmp;
  if (!PKCS5_PBKDF2_HMAC(
    pass.c_str(),
    pass.length(),
    salt.data(),
    WIDTH_SALT,
    PBKDF2_ITERATIONS,
    EVP_sha256(),
    WIDTH_HASH,
    derived_tmp.data()
  )) {
    cli::fatal("failed to derive master key from password");
  }

  this->key = derived_tmp;

  // Clear the salt, master hash from memory.
  std::fill(salt.begin(), salt.end(), 0);
  std::fill(master.begin(), master.end(), 0);
  std::fill(derived_tmp.begin(), derived_tmp.end(), 0);
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

  fat.clear();
  store_fat();
}

Container::~Container() {
  std::fill(salt.begin(), salt.end(), 0);
  std::fill(master.begin(), master.end(), 0);
  std::fill(key.begin(), key.end(), 0);

  container.close(); 
  fat.clear();
}

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

  std::ostringstream fat_stream;
  for (const FATEntry &entry : fat)
    serialize(fat_stream, entry);
  const std::string serialized_fat = fat_stream.str();

  // Serialize each entry.
  if (!container.write(serialized_fat.data(), entries * sizeof(FATEntry)))
    cli::fatal("(store_fat): failed to write FAT data to the container: " + name);

  // Flush the container to ensure the FAT is written.
  container.flush();
  if (!container)
    cli::fatal("(store_fat): failed to flush container: " + name);
}

void Container::load_fat() {
  // Attempt to seek to the FAT offset.
  container.clear();
  container.seekg(OFFSET_FAT, std::ios::beg);
  if (!container)
    cli::fatal("(load_fat): failed to seek to FAT offset: " + name);

  // Read the number of entries in the FAT.
  std::uint32_t entries;
  if (!container.read(
    reinterpret_cast<char *>(&entries), 
    sizeof(std::uint32_t)
  )) {
    cli::fatal("(load_fat): failed to read FAT entries from container: " + name);
  }

  std::vector<unsigned char> fat_data(entries * sizeof(FATEntry));
  container.read(
    reinterpret_cast<char *>(fat_data.data()), 
    fat_data.size()
  );
  if (container.gcount() != fat_data.size())
    cli::fatal("(load_fat): failed to read FAT entries from container: " + name);

  std::istringstream fat_stream(
    std::string(fat_data.begin(), fat_data.end())
  );

  fat.clear();
  while (fat_stream) {
    FATEntry entry;
    if (deserialize(fat_stream, entry))
      fat.push_back(entry);
  }
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

void Container::store_file(const std::string &in_path) {
  std::vector<unsigned char> contents = gen_read_file(in_path);

  // Compress file data.
  std::stringstream compressed_stream;
  {
    ios::filtering_ostream out;
    out.push(ios::zlib_compressor());
    out.push(compressed_stream);
    out.write(reinterpret_cast<const char*>(contents.data()), contents.size());
    out.flush();
  }

  // Stringify the compressed stream data.
  std::string compressed_data_str = compressed_stream.str();
  std::vector<unsigned char> compressed_data(
    compressed_data_str.begin(), 
    compressed_data_str.end()
  );

  std::array<unsigned char, 16> iv = generate_iv();
  std::vector<unsigned char> enc_data = aes_encrypt(compressed_data, key, iv);

  // Check if an entry of the same file name exists.
  auto it = std::find_if(
    fat.begin(), 
    fat.end(), 
    [&in_path](const FATEntry& entry) -> bool {
      return entry.filename == in_path;
    }
  );

  // If an entry exists, update it.
  if (it != fat.end()) {
    FATEntry &existing = *it;
    existing.original_size = contents.size();
    existing.compressed_size = compressed_data.size();
    existing.encrypted_size = enc_data.size();
    existing.last_modified = fs::last_write_time(in_path);
    std::copy(iv.begin(), iv.end(), existing.iv.begin());
    existing.checksum = compute_checksum(in_path);

    // Reuse existing space if the new entry is smaller.
    if (existing.encrypted_size >= enc_data.size()) {
      container.seekp(existing.offset, std::ios::beg);
      if (!container.write(
        reinterpret_cast<const char *>(enc_data.data()),
        enc_data.size()
      )) {
        cli::fatal("(store_file): failed to write encrypted data to container: " + name);
      }
    } else {
      // Append to the end of the container.
      container.seekp(0, std::ios::end);
      existing.offset = container.tellp();
      if (!container.write(
        reinterpret_cast<const char *>(enc_data.data()), 
        enc_data.size()
      )) {
        cli::fatal("(store_file): failed to write encrypted data to container: " + name);
      }
    }
  } else {
    // Append a new entry to the table.
    FATEntry entry;
    entry.filename = in_path;
    entry.original_size = contents.size();
    entry.compressed_size = compressed_data.size();
    entry.encrypted_size = enc_data.size();
    entry.iv = iv;
    entry.last_modified = fs::last_write_time(in_path);
    entry.checksum = compute_checksum(in_path);

    container.seekp(0, std::ios::end);
    entry.offset = container.tellp();
    if (!container.write(
      reinterpret_cast<const char *>(enc_data.data()), 
      enc_data.size()
    )) {
      cli::fatal("(store_file): failed to write encrypted data to container: " + name);
    }

    fat.push_back(entry);
  }

  store_fat();
}

void Container::load_file(const std::string &out_path) {
  return;
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