//>==- fat.h --------------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#ifndef SOTERIA_FAT_H
#define SOTERIA_FAT_H

#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

namespace soteria {

struct FATEntry {
  /// Name of the file.
  std::string filename;

  /// Length of the file.
  uint64_t size;

  /// Offset of the file in the container.
  uint64_t offset;

  /// IV for the file.
  std::vector<unsigned char> iv;

  /// Whether the file is compressed.
  bool is_compressed : 1;

  /// Most recent modification timestamp.
  std::time_t last_modified;

  /// SHA-256 checksum of the file.
  std::string checksum; 
};

/// \returns A FATEntry with file metadata at \p file_path.
/// \param file_path The path to the file to fetch metadata for.
FATEntry get_metadata(const std::string &file_path);

} // end namespace soteria

#endif // SOTERIA_FAT_H
