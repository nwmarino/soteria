//>==- fat.cpp ------------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#include "boost/filesystem.hpp"

#include "../../include/cli/cli.h"
#include "../../include/core/fat.h"

namespace fs = boost::filesystem;

using namespace soteria;

FATEntry soteria::get_metadata(const std::string &file_path) {
  if (!fs::exists(file_path))
    cli::fatal("file does not exist: " + file_path);

  // Construct a new FAT entry given the file.
  FATEntry entry;
  entry.filename = fs::path(file_path).filename().string();
  entry.size = fs::file_size(file_path);
  entry.last_modified = fs::last_write_time(file_path);
  entry.is_compressed = false; // default
  entry.checksum = std::string();
  return entry;
}
