//>==- fat.cpp ------------------------------------------------------------==<//
//
// This file implements functions to serialize and deserialize FAT entries.
//
//>==----------------------------------------------------------------------==<//

#include "boost/filesystem/operations.hpp"

#include "cli/cli.h"
#include "core/fat.h"
#include "utils/encryption.h"

namespace fs = boost::filesystem;

using namespace soteria;

FATEntry soteria::get_metadata(const std::string &file_path) {
  if (!fs::exists(file_path))
    cli::fatal("[fat_get_metadata] file does not exist: " + file_path);

  // Construct a new FAT entry given the file.
  FATEntry entry;
  entry.filename = fs::path(file_path).filename().string();
  entry.original_size = fs::file_size(file_path);
  entry.encrypted_size = 0;
  entry.compressed_size = 0;
  entry.last_modified = fs::last_write_time(file_path);
  entry.checksum = compute_checksum(file_path);
  return entry;
}

void soteria::serialize(std::ostringstream &stream, const FATEntry &entry) {
  if (entry.filename.size() > 32)
    cli::fatal("[fat_serialize] filename too long: " + entry.filename);

  // Create a filename padded to 32 bytes, and write it.
  std::string padded_filename = entry.filename;
  padded_filename.resize(32, '\0');
  stream.write(padded_filename.data(), 32);
  
  // Write the original, compressed, and encrypted sizes.
  stream.write(
    reinterpret_cast<const char *>(&entry.original_size), 
    sizeof(entry.original_size)
  );
  stream.write(
    reinterpret_cast<const char *>(&entry.compressed_size), 
    sizeof(entry.compressed_size)
  );
  stream.write(
    reinterpret_cast<const char *>(&entry.encrypted_size), 
    sizeof(entry.encrypted_size)
  );

  // Write the offset.
  stream.write(
    reinterpret_cast<const char *>(&entry.offset),
    sizeof(entry.offset)
  );

  // Write the last modified timestamp.
  int64_t last_modified_time = static_cast<int64_t>(entry.last_modified);
  stream.write(
    reinterpret_cast<const char *>(&last_modified_time), 
    sizeof(last_modified_time)
  );
  
  // Write the IV, checksum.
  stream.write(
    reinterpret_cast<const char *>(entry.iv.data()), 
    entry.iv.size()
  );
  stream.write(
    reinterpret_cast<const char *>(entry.checksum.data()), 
    entry.checksum.size()
  );
}

bool soteria::deserialize(std::istringstream &stream, FATEntry &entry) {
  try {
    // Read in the filename.
    char filename_buf[32] = {};
    stream.read(filename_buf, 32);
    if (stream.gcount() != 32)
      return false;

    // Convert buffer to string, trimming padding.
    entry.filename = std::string(filename_buf);

    // Read in the originbal, compressed, and encrypted sizes.
    stream.read(
      reinterpret_cast<char *>(&entry.original_size),
      sizeof(entry.original_size)
    );
    stream.read(
      reinterpret_cast<char *>(&entry.compressed_size), 
      sizeof(entry.compressed_size)
    );
    stream.read(
      reinterpret_cast<char *>(&entry.encrypted_size), 
      sizeof(entry.encrypted_size)
    );
    
    // Read in the offset.
    stream.read(
      reinterpret_cast<char *>(&entry.offset), 
      sizeof(entry.offset)
    );

    // Read in the last modified timestamp.
    uint64_t last_modified;
    stream.read(
      reinterpret_cast<char *>(&last_modified), 
      sizeof(last_modified)
    );
    entry.last_modified = static_cast<time_t>(last_modified);

    // Read in the IV, checksum.
    stream.read(
      reinterpret_cast<char *>(entry.iv.data()), 
      entry.iv.size()
    );
    stream.read(
      reinterpret_cast<char *>(entry.checksum.data()), 
      entry.checksum.size()
    );

    return true;
  } catch(...) {
    return false;
  }
}
