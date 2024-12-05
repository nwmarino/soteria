//>==- file.h -------------------------------------------------------------==<//
//
// This header file declares file I/O functions used to facilitate reading in
// files and writing in binary mode.
//
//>==----------------------------------------------------------------------==<//

#ifndef SOTERIA_FILE_H
#define SOTERIA_FILE_H

#include <fstream>
#include <string>
#include <vector>

#include "../cli/cli.h"

namespace soteria {

/// \returns The contents of the file at \p path.
inline std::vector<unsigned char> gen_read_file(const std::string &path) {
  // Attempt to open the file for reading.
  // *Seeks to the end to read in the content length.
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file || !file.is_open())
    cli::fatal("[gen_read_file] unable to open file for reading: " + path);

  // Fetch the size of the file contents.
  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);

  // Instantiate a buffer and attempt to read the contents to it.
  std::vector<unsigned char> buffer(size);
  if (!file.read(reinterpret_cast<char *>(buffer.data()), size))
    cli::fatal("[gen_read_file] unable to read file: " + path);

  // Close the file and return its contents.
  file.close();
  return buffer;
}

/// Writes binary data to the file at \p path.
inline void bin_write_file(const std::string &path, 
                           const std::vector<unsigned char> &data) {
  // Attempt to open the file for binary writing.
  std::ofstream file(path, std::ios::binary);
  if (!file || !file.is_open())
    cli::fatal("[bin_write_file] unable to open file for writing: " + path);

  // Attempt to write the given data to the file.
  if (!file.write(reinterpret_cast<const char *>(data.data()), data.size()))
    cli::fatal("[bin_write_file] unable to write to file: " + path);

  file.close();
}

} // end namespace soteria

#endif // SOTERIA_FILE_H
