//>==- fat.h --------------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#ifndef SOTERIA_FAT_H
#define SOTERIA_FAT_H

#include <array>
#include <cstdint>
#include <ctime>
#include <string>

namespace soteria {

/// File Allocation Table metadata for a file entry.
struct FATEntry {
  /// Name of the file.
  std::string filename;

  /// Original size of the file contents.
  std::uint64_t original_size;

  /// Encrypted size of the file contents.
  std::uint64_t encrypted_size;

  /// Compressed size of the file contents.
  std::uint64_t compressed_size;

  /// Offset of the file in the container.
  std::uint64_t offset;

  /// Most recent modification timestamp.
  std::time_t last_modified;

  /// Initialization vector for the file.
  std::array<unsigned char, 16> iv;

  /// SHA-256 checksum of the file.
  std::array<unsigned char, 32> checksum;
};

/// \returns A FATEntry with file metadata at \p file_path.
/// \param file_path The path to the file to fetch metadata for.
FATEntry get_metadata(const std::string &file_path);

void serialize(std::ostringstream &stream, const FATEntry &entry);
bool deserialize(std::istringstream &stream, FATEntry &entry);

} // end namespace soteria

#endif // SOTERIA_FAT_H
