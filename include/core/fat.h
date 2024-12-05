//>==- fat.h --------------------------------------------------------------==<//
//
// This header file declares an entry in the File Allocation Table (FAT) used
// in containers to track encrypted file metadata.
//
//>==----------------------------------------------------------------------==<//

#ifndef SOTERIA_FAT_H
#define SOTERIA_FAT_H

#include <array>
#include <cstdint>
#include <ctime>
#include <sstream>
#include <string>

namespace soteria {

constexpr uint32_t MAX_FILENAME_LEN = 32;

/// FAT metadata for a file entry.
struct FATEntry {
  std::string filename;
  uint64_t original_size;
  uint64_t encrypted_size;
  uint64_t compressed_size;
  uint64_t offset;
  time_t last_modified;
  std::array<unsigned char, 16> iv;
  std::array<unsigned char, 32> checksum;
};

/// \returns A FATEntry with metadata for the file at \p file_path.
FATEntry get_metadata(const std::string &file_path);

/// Serializes the FATEntry \p entry to the output stream \p stream.
void serialize(std::ostringstream &stream, const FATEntry &entry);

/// Deserializes the FATEntry \p entry from the input stream \p stream.
/// \returns `true` if the entry could be deserialized.
bool deserialize(std::istringstream &stream, FATEntry &entry);

} // end namespace soteria

#endif // SOTERIA_FAT_H
