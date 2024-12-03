//>==- fat.cpp ------------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#include "boost/filesystem.hpp"

#include "../../include/cli/cli.h"
#include "../../include/core/fat.h"
#include "../../include/utils/encryption.h"

namespace fs = boost::filesystem;

using namespace soteria;

FATEntry soteria::get_metadata(const std::string &file_path) {
  if (!fs::exists(file_path))
    cli::fatal("file does not exist: " + file_path);

  // Construct a new FAT entry given the file.
  FATEntry entry;
  entry.filename = fs::path(file_path).filename().string();
  entry.original_size = fs::file_size(file_path);
  entry.encrypted_size = 0;
  entry.compressed_size = 0;
  entry.last_modified = fs::last_write_time(file_path);
  entry.is_compressed = false;
  entry.checksum = compute_checksum(file_path);
  return entry;
}
