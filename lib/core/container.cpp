//>==- container.cpp ------------------------------------------------------==<//
//
// The following source implements the container class and its respective
// methods.
//
// Container files have the following reserved layout (in bytes):
//
// { [version : 1][salt : 16][hash : 32][FAT entries : ...] }
//
//>==----------------------------------------------------------------------==<//

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>

#include "boost/filesystem/operations.hpp"
#include "boost/iostreams/filtering_stream.hpp"
#include "boost/iostreams/filter/zlib.hpp"
#include "openssl/evp.h"

#include "cli/cli.h"
#include "core/container.h"
#include "core/fat.h"
#include "include/core/version.h"
#include "utils/encryption.h"
#include "utils/file.h"

namespace fs = boost::filesystem;
namespace ios = boost::iostreams;

using namespace soteria;

/// Default number of iterations to use for PBKDF2.
constexpr std::size_t PBKDF2_ITERATIONS = 100000;

/// Default chunk size for container compaction.
constexpr std::size_t CHUNK_SIZE = 1024 * 128; // 128 KB

/// Byte-widths.
constexpr std::size_t WIDTH_VERSION = 4;
constexpr std::size_t WIDTH_SIZE = 8;
constexpr std::size_t WIDTH_IV = 16;
constexpr std::size_t WIDTH_SALT = 16;
constexpr std::size_t WIDTH_HASH = 32;

/// Constant offsets for the reserved container layout.
constexpr std::size_t OFFSET_VERSION = 0;
constexpr std::size_t OFFSET_MASTER_SALT = OFFSET_VERSION + WIDTH_VERSION;
constexpr std::size_t OFFSET_MASTER_HASH = OFFSET_MASTER_SALT + WIDTH_SALT;
constexpr std::size_t OFFSET_FAT_IV = OFFSET_MASTER_HASH + WIDTH_HASH;
constexpr std::size_t OFFSET_FAT_SIZE = OFFSET_FAT_IV + WIDTH_IV;
constexpr std::size_t OFFSET_FAT = OFFSET_FAT_SIZE + WIDTH_SIZE;

Container::Container(const std::string &path,
                     const std::string &pass) 
    : path(path), name(path.substr(path.find_last_of('/') + 1)) {
  if (!fs::exists(this->path))
    cli::fatal("[container] does not exist: " + name);

  container.open(
    this->path,
    std::ios::binary | std::ios::in | std::ios::out
  );

  if (!container || !container.is_open())
    cli::fatal("[container] failed to open: " + name);

  // Check the version.
  load_version();

  // Load the stored master hash and compare it to the input password.
  load_master();
  if (!match_password(pass, this->master, this->salt)) {
    container.close();
    std::fill(salt.begin(), salt.end(), 0);
    std::fill(master.begin(), master.end(), 0);
    cli::fatal("[container] incorrect password: " + pass);
  }

  // Derive the encryption key from the password.
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
    cli::fatal("[container] failed to derive encryption key: " + name);
  }

  this->key = derived_tmp;

  // Clear the salt, master hash from memory.
  std::fill(salt.begin(), salt.end(), 0);
  std::fill(master.begin(), master.end(), 0);
  std::fill(derived_tmp.begin(), derived_tmp.end(), 0);

  load_fat(); // Load the FAT from the container.
}

Container::Container(const std::string &name, 
                     const std::string &path,
                     const std::string &pass) : name(name), path(path) {
  if (fs::exists(this->path))
    cli::fatal("[container] already exists: " + name);

  // Create the new container.
  container.open(
    this->path,
    std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc
  );

  if (!container.is_open())
    cli::fatal("[container] failed to create: " + name);

  // Check that the current version is valid to store.
  const std::string major_str = std::to_string(VERSION_MAJOR);
  if (major_str.size() > 2)
    cli::fatal("[container] invalid version, major too large: " + major_str);

  const std::string minor_str = std::to_string(VERSION_MINOR);
  if (minor_str.size() > 2)
    cli::fatal("[container] invalid version, minor too large: " + minor_str);

  version.at(0) = std::string(major_str).c_str()[0];
  version.at(1) = std::string(major_str).c_str()[1];
  version.at(2) = std::string(minor_str).c_str()[0];
  version.at(3) = std::string(minor_str).c_str()[1];
  store_version();

  // Hash the master password and store it to the container.
  this->salt = generate_rand(WIDTH_SALT);
  this->master = hash_password(pass, salt);

  // Derive the encryption key from the password.
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
    cli::fatal("[container] failed to derive encryption key: " + name);
  }

  this->key = derived_tmp;
  store_master(); // Clears salt, master from memory.

  // Write the remaining reserved space as empty.
  std::vector<unsigned char> empty_space(2048 - container.tellp(), 0);
  if (!container.write(
    reinterpret_cast<const char *>(empty_space.data()), 
    empty_space.size()
  )) {
    cli::fatal("[container] failed to allocate space for: " + name);
  }
}

Container::~Container() {
  store_fat();

  // Clear all sensitive data from memory.
  std::fill(salt.begin(), salt.end(), 0);
  std::fill(master.begin(), master.end(), 0);
  std::fill(key.begin(), key.end(), 0);
  fat.clear();

  // Close the container file.
  container.close(); 
}

Container *Container::create(const std::string &path,
                             const std::string &pass) { 
  return new Container(
    path.substr(path.find_last_of('/') + 1), 
    path,
    pass
  );
}

Container *Container::open(const std::string &path, const std::string &pass)
{ return new Container(path, pass); }

/// Writes container::version to the container.
///
/// This method should only ever be called by the opening constructor, as after
/// creation, a version should be immutable.
void Container::store_version() {
  // Clear the container position for writing.
  container.clear();
  container.seekp(OFFSET_VERSION, std::ios::beg);

  // Write the version to the container.
  if (!container.write(
    reinterpret_cast<const char *>(version.data()),
    WIDTH_VERSION
  )) {
    cli::fatal("[store_version] failed to write version: " + name);
  }

  // Flush the container to ensure the version is written.
  if (!container.flush())
    cli::fatal("[store_version] failed to flush stream: " + name);
}

void Container::load_version() {
  // Clear the container position for reading.
  container.clear();
  container.seekg(OFFSET_VERSION, std::ios::beg);

  // Attempt to read the version from the container.
  if (!container.read(reinterpret_cast<char *>(version.data()), WIDTH_VERSION))
    cli::fatal("[load_version] failed to read version: " + name);

  // Stringify the current version of the program.
  const std::string major_str = std::to_string(VERSION_MAJOR);
  const std::string minor_str = std::to_string(VERSION_MINOR);
  std::array<unsigned char, 4> curr_version_str;
  curr_version_str.at(0) = std::string(major_str).c_str()[0];
  curr_version_str.at(1) = std::string(major_str).c_str()[1];
  curr_version_str.at(2) = std::string(minor_str).c_str()[0];
  curr_version_str.at(3) = std::string(minor_str).c_str()[1];

  // Check that the versions match.
  if (std::string(version.begin(), version.end()) != std::string(curr_version_str.begin(), curr_version_str.end())) {
    // Stringify the read in version.
    std::string container_version_str;
    container_version_str.push_back(version.at(0));
    container_version_str.push_back(version.at(1));
    container_version_str.push_back('.');
    container_version_str.push_back(version.at(2));
    container_version_str.push_back(version.at(3));
    
    cli::fatal("[load_version] current version (" + std::to_string(VERSION_MAJOR) 
      + '.' + std::to_string(VERSION_MINOR) + ") incompatible with container: " 
      + name + ", expected " + container_version_str);
  }
}

/// Writes container::master to the container.
///
/// This function writes the master password hash with a new salt to the 
/// container on the following byte layout:
///
/// { [salt : 16][hash : 32] ... }
///
/// This function also clears the stored salt, hash from container memory.
void Container::store_master() {
  // Clear the container positioning for writing.
  container.clear();
  container.seekp(OFFSET_MASTER_SALT, std::ios::beg);

  // Write the salt at its offset.
  assert(container.tellp() == OFFSET_MASTER_SALT);
  if (!container.write(
    reinterpret_cast<char *>(salt.data()), 
    WIDTH_SALT
  )) {
    cli::fatal("[store_master] failed to write salt: " + name);
  }

  // Write the password hash at its offset.
  assert(container.tellp() == OFFSET_MASTER_HASH);
  if (!container.write(
    reinterpret_cast<char *>(master.data()), 
    WIDTH_HASH
  )) {
    cli::fatal("[store_master] failed to write hash: " + name);
  }

  // Clear the stored salt, hash from memory.
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
  container.seekg(OFFSET_MASTER_SALT, std::ios::beg);

  // Read the stored salt.
  std::vector<unsigned char> tmp_salt(WIDTH_SALT);
  assert(container.tellg() == OFFSET_MASTER_SALT);
  if (!container.read(
    reinterpret_cast<char *>(tmp_salt.data()),
    tmp_salt.size()
  )) {
    cli::fatal("[load_master] failed to read salt: " + name);
  }

  // Read the stored hash.
  std::vector<unsigned char> tmp_hash(WIDTH_HASH);
  assert(container.tellg() == OFFSET_MASTER_HASH);
  if (!container.read(
    reinterpret_cast<char *>(tmp_hash.data()), 
    tmp_hash.size()
  )) {
    cli::fatal("[load_master] failed to read hash: " + name);
  }

  // Copy the temporary salt, hash to the container and clear them from memory.
  this->salt = tmp_salt;
  this->master = tmp_hash;
  std::fill(tmp_salt.begin(), tmp_salt.end(), 0);
  std::fill(tmp_hash.begin(), tmp_hash.end(), 0);
}

/// Stores the current state of the FAT to the container.
///
/// This method does not modify the current FAT state.
void Container::store_fat() {
  // Clear the container positioning for writing.
  container.clear();
  container.seekp(OFFSET_FAT_IV, std::ios::beg);
  if (!container)
    cli::fatal("[store_fat] failed to update FAT: " + name);

  // Attempt to write a new IV for the FAT.
  std::array<unsigned char, 16> iv = generate_iv();
  if (!container.write(
    reinterpret_cast<const char *>(iv.data()), 
    WIDTH_IV
  )) {
    cli::fatal("[store_fat] failed to store FAT IV: " + name);
  }

  // Serialize all FAT entries and stringify the stream.
  std::ostringstream fat_stream;
  for (const FATEntry &entry : fat) {
    serialize(fat_stream, entry);
  }
  const std::string serialized_fat = fat_stream.str();

  // Encrypt the serialized FAT.
  std::vector<unsigned char> enc_fat = aes_encrypt(
    std::vector<unsigned char>(serialized_fat.begin(), serialized_fat.end()), 
    key,
    iv
  );

  // Write the size of the encrypted FAT to the container.
  const uint64_t size = enc_fat.size();
  container.seekp(OFFSET_FAT_SIZE, std::ios::beg);
  if (!container.write(
    reinterpret_cast<const char *>(&size), 
    WIDTH_SIZE
  )) {
    cli::fatal("[store_fat] failed to store FAT size: " + name);
  }

  // Write the encrypted FAT to the container.
  if (!container.write(
    reinterpret_cast<const char *>(enc_fat.data()), 
    enc_fat.size())
  ) {
    cli::fatal("[store_FAT] failed to update FAT entries: " + name);
  }

  // Flush the container to ensure the FAT is written.
  if (!container.flush())
    cli::fatal("[store_fat] failed to flush stream: " + name);
}

/// Loads the stored container FAT to memory.
///
/// This method does not modify the stored FAT state.
void Container::load_fat() {
  // Clear the container positioning for reading.
  container.clear();
  container.seekg(OFFSET_FAT_IV, std::ios::beg);
  if (!container)
    cli::fatal("[load_fat] failed to reach FAT: " + name);

  // Read the IV for the FAT.
  std::array<unsigned char, 16> iv;
  if (!container.read(
    reinterpret_cast<char *>(iv.data()), 
    WIDTH_IV
  )) {
    cli::fatal("[load_fat] failed to load FAT IV: " + name);
  }

  // Read the size of the encrypted FAT.
  uint64_t size;
  container.seekg(OFFSET_FAT_SIZE, std::ios::beg);
  if (!container.read(
    reinterpret_cast<char *>(&size), 
    WIDTH_SIZE
  )) {
    cli::fatal("[load_fat] failed to load FAT size: " + name);
  }

  // Read the encrypted FAT from the container.
  std::vector<unsigned char> enc_fat(size);
  if (!container.read(
    reinterpret_cast<char *>(enc_fat.data()), 
    enc_fat.size()
  )) {
    cli::fatal("[load_fat] failed to load FAT entries: " + name);
  }

  // Check if the number of entries read matches the expected count.
  if (container.gcount() != size)
    cli::fatal("[load_fat] failed to load FAT entries: " + name);

  // Decrypt the FAT.
  std::vector<unsigned char> dec_fat = aes_decrypt(enc_fat, key, iv);

  // Initialize a string stream to deserialize the decrypted FAT.
  std::istringstream fat_stream(std::string(dec_fat.begin(), dec_fat.end()));

  // Clear the FAT and attempt to read deserialized entries from the stream.
  fat.clear();
  while (fat_stream) {
    FATEntry entry;
    if (deserialize(fat_stream, entry))
      fat.push_back(entry);
  }
}

bool Container::delete_file(const std::string &path) {
  // Check if the file exists in the FAT.
  auto it = std::find_if(
    fat.begin(), 
    fat.end(), 
    [&path](const FATEntry& entry) -> bool {
      return entry.filename == path;
    }
  );

  if (it == fat.end()) 
    return false;

  const uint64_t offset = it->offset;
  const uint64_t size = it->encrypted_size;

  // Clear the file data from the container.
  container.seekp(offset, std::ios::beg);
  std::vector<unsigned char> empty_data(size, 0);
  if (!container.write(
    reinterpret_cast<const char *>(empty_data.data()), 
    empty_data.size()
  )) {
    cli::fatal("[delete_file] failed to clear file data: " + name);
  }

  fat.erase(it); // Remove the file from the FAT.
  return true;
}

/// Dumps metadata for each FAT entry to the file at path.
///
/// This function loads the FAT into container memory and does not clear it.
void Container::list(const std::string &path) {
  // Attempt to open the dump file.
  std::ofstream output(path);
  if (!output || !output.is_open())
    cli::fatal("[container_list] failed to open output file: " + path);

  // Write a formatted header.
  output << std::left << std::setw(30) << "Filename"
         << std::setw(15) << "Original Size"
         << std::setw(25) << "Last Modified" 
         << std::endl;

  // Write a separator line.
  output << std::string(58, '-') << std::endl;

  // Dump each FAT entry to the output file.
  for (const FATEntry &entry : fat) {
    // Convert the integer timestamp to a formatted timestamp.
    std::tm *time_info = std::gmtime(&entry.last_modified);
    if (!time_info)
      cli::fatal("[container_list] failed to convert timestamp to string");

    // Stringify the timestamp.
    std::ostringstream timestamp_str;
    timestamp_str << std::put_time(time_info, "%Y-%m-%d %H:%M:%S");

    // Write the entry metadata to the text file.
    output << std::setw(30) << entry.filename
           << std::setw(15) << entry.original_size
           << std::setw(25) << timestamp_str.str() 
           << std::endl;
  }

  output.close();
}

void Container::compact() {
  if (fat.empty())
    return;

  // Create a temporary container file to read compacted data into.
  const std::string tmp_file = this->path + ".tmp";
  std::ofstream tmp_container(tmp_file, std::ios::binary | std::ios::out);
  if (!tmp_container || !tmp_container.is_open())
    cli::fatal("[compact] failed to create temporary container: " + name);

  // Reserve space in the new container.
  tmp_container.seekp(2048 - 1, std::ios::beg);
  tmp_container.write("", 1);

  // For each FAT entry, write its data in chunks to the new container.
  std::streampos new_offset = 2048;
  for (FATEntry &entry : this->fat) {
    // Instantiate a buffer to read file data in chunks.
    std::vector<unsigned char> buffer(CHUNK_SIZE);
    container.seekg(entry.offset, std::ios::beg);
    std::size_t remaining = entry.encrypted_size;
    std::streampos new_entry_offset = new_offset;

    // Repeat until all data is read.
    while (remaining > 0) {
      std::size_t to_read = std::min(CHUNK_SIZE, remaining);
      container.read(reinterpret_cast<char *>(buffer.data()), to_read);
      if (container.gcount() != to_read)
        cli::fatal("[compact] failed to read data from container.");

      if (!tmp_container.write(reinterpret_cast<char *>(buffer.data()), to_read))
        cli::fatal("[compact] failed to write data to temporary container.");

      remaining -= to_read;
      new_offset += to_read;
    }

    // Update the file's FAT entry offset.
    entry.offset = new_entry_offset;
  }

  // Close the temporary file.
  container.close();
  tmp_container.close();

  if (!fs::remove(path.c_str()))
    cli::fatal("[compact] failed to remove original container file.");

  fs::rename(tmp_file, path);

  // Reopen the container file.
  container.open(
    path,
    std::ios::binary | std::ios::in | std::ios::out
  );
}

bool Container::contains(const std::string &name) const {
  return std::find_if(
    fat.begin(), 
    fat.end(), 
    [&name](const FATEntry &entry) -> bool {
      return entry.filename == name;
    }
  ) != fat.end();
}

FATEntry &Container::get_entry(const std::string &name) const {
  auto it = std::find_if(
    fat.begin(), 
    fat.end(), 
    [&name](const FATEntry &entry) -> bool {
      return entry.filename == name;
    }
  );

  if (it == fat.end())
    cli::fatal("[get_entry] unresolved file in container: " + name);

  return *it;
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

  // Generate an IV for this file and encrypt its compressed data.
  std::array<unsigned char, 16> iv = generate_iv();
  std::vector<unsigned char> enc_data = aes_encrypt(compressed_data, key, iv);

  // If an entry exists, update it.
  if (contains(in_path) 
      || contains(in_path.substr(in_path.find_last_of('/') + 1))) {
    FATEntry &existing = get_entry(in_path);
    existing.original_size = contents.size();
    existing.compressed_size = compressed_data.size();
    existing.encrypted_size = enc_data.size();
    existing.last_modified = fs::last_write_time(in_path);
    existing.iv = iv;
    existing.checksum = compute_checksum(in_path);

    // Reuse existing space if the new entry is smaller.
    if (existing.encrypted_size >= enc_data.size()) {
      container.seekp(existing.offset, std::ios::beg);
      if (!container.write(
        reinterpret_cast<const char *>(enc_data.data()),
        enc_data.size()
      )) {
        cli::fatal("[store_file] failed to overwrite encrypted file: " + name);
      }
    } else {
      // Append to the end of the container.
      container.seekp(0, std::ios::end);
      existing.offset = container.tellp();
      if (!container.write(
        reinterpret_cast<const char *>(enc_data.data()), 
        enc_data.size()
      )) {
        cli::fatal("[store_file] failed to store encrypted file: " + name);
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

    // Seek to the end of the container to append the new file.
    container.seekp(0, std::ios::end);
    entry.offset = container.tellp();

    // Attempt to store the file.
    if (!container.write(
      reinterpret_cast<const char *>(enc_data.data()), 
      enc_data.size()
    )) {
      cli::fatal("[store_file] failed to store new encrypted file: " + name);
    }

    fat.push_back(entry);
  }
}

void Container::load_file(const std::string &out_path) {
  // Attempt to get the FAT entry for the output path. Will fatal if unresolved.
  const FATEntry &entry = get_entry(out_path);

  // Attempt to read target file data from its offset.
  container.seekg(entry.offset, std::ios::beg);
  std::vector<unsigned char> enc_data(entry.encrypted_size);
  container.read(
    reinterpret_cast<char *>(enc_data.data()), 
    enc_data.size()
  );

  // Check that the read data matches the expected size.
  if (container.gcount() != static_cast<std::streamsize>(entry.encrypted_size))
    cli::fatal("[load_file] failed to read encrypted data from container: " + name);

  // Decrypt the read file data.
  std::vector<unsigned char> dec_data = aes_decrypt(enc_data, key, entry.iv);

  // Decompress the decrypted data.
  std::stringstream dec_stream(std::string(dec_data.begin(), dec_data.end()));
  ios::filtering_istream in;
  in.push(ios::zlib_decompressor());
  in.push(dec_stream);

  // Read the decompressed data from the stream.
  std::vector<unsigned char> file_data;
  while (in) {
    char buffer[1024];
    in.read(buffer, sizeof(buffer));
    file_data.insert(
      file_data.end(), 
      buffer, 
      buffer + in.gcount()
    );
  }

  // Compare the checksum.
  if (compute_checksum(file_data) != entry.checksum)
    cli::fatal("[load_file] checksum mismatch: " + out_path);
  else
    cli::info("[load_file] " + out_path + " checksum matches!");

  // Create the decrypted file at the output path.
  bin_write_file(out_path, file_data);
}
