//>==- file.cpp -----------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#include <fstream>

#include "../../include/cli/cli.h"
#include "../../include/utils/file.h"

using namespace soteria;

std::vector<unsigned char> soteria::gen_read_file(const std::string &path) {
  // Attempt to open the file for reading.
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file.is_open())
    cli::fatal("unable to open file for reading: " + path);

  // Fetch the size of the file contents.
  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);

  // Instantiate a buffer and attempt to read the contents to it.
  std::vector<unsigned char> buf(size);
  if (!file.read(reinterpret_cast<char *>(buf.data()), size))
    cli::fatal("unable to read file: " + path);

  // Close the file and return its contents.
  file.close();
  return buf;
}

void soteria::bin_write_file(const std::string &path, 
                             const std::vector<unsigned char> &data) {
  // Attempt to open the file for binary writing.
  std::ofstream file(path, std::ios::binary);
  if (!file.is_open())
    cli::fatal("unable to open file for writing: " + path);

  // Attempt to write the given data to the file.
  if (!file.write(reinterpret_cast<const char *>(data.data()), data.size()))
    cli::fatal("unable to write to file: " + path);

  file.close();
}
