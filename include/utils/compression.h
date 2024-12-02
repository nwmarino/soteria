//>==- compression.h ------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#ifndef SOTERIA_COMPRESSION_H
#define SOTERIA_COMPRESSION_H

#include <vector>

namespace soteria {

/// \returns The decompressed data from \p data.
/// \param data The compressed data to decompress.
std::vector<unsigned char> decompress(std::vector<unsigned char> &data);

/// \returns The compressed data from \p data.
/// \param data The data to compress.
std::vector<unsigned char> compress(std::vector<unsigned char> &data);

} // end namespace soteria

#endif // SOTERIA_COMPRESSION_H
