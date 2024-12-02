//>==- file.h -------------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#ifndef SOTERIA_FILE_H
#define SOTERIA_FILE_H

#include <string>
#include <vector>

namespace soteria {

/// \returns The generic contents of a file.
/// \param path The path to the file.
std::vector<unsigned char> gen_read_file(const std::string &path);

/// Writes binary data to a file.
/// \param path The path to the file.
/// \param data The data to write.
void bin_write_file(const std::string &path, const std::vector<unsigned char> &data);

} // end namespace soteria

#endif // SOTERIA_FILE_H
