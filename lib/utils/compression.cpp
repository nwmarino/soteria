//>==- compression.cpp ----------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#include <sstream>
#include <string>
#include <vector>

#include "boost/iostreams/filtering_stream.hpp"
#include "boost/iostreams/filter/zlib.hpp"

#include "../../include/utils/compression.h"

namespace bios = boost::iostreams;

using namespace soteria;

std::vector<unsigned char> soteria::decompress(std::vector<unsigned char> &data) {
  // Decompress the data.
  std::stringstream compressed_stream(std::string(data.begin(), data.end()));
  std::stringstream decompressed_stream;

  // Create a decompression stream.
  bios::filtering_istream decompress_stream;
  decompress_stream.push(bios::zlib_decompressor());
  decompress_stream.push(decompressed_stream);

  // Decompress the filtered stream.
  decompressed_stream << decompress_stream.rdbuf();
  std::string decompressed = decompressed_stream.str();

  // Return the decompressed data.
  return std::vector<unsigned char>(
    decompressed.begin(), 
    decompressed.end()
  );
}

std::vector<unsigned char> soteria::compress(std::vector<unsigned char> &data) {
  // Compress the data.
  std::stringstream compressed_stream;
  bios::filtering_ostream compress_stream;
  compress_stream.push(bios::zlib_compressor());
  compress_stream.push(compressed_stream);

  // Compress the filtered stream.
  compress_stream.write(reinterpret_cast<const char *>(data.data()), data.size());
  bios::close(compress_stream);
  std::string compressed = compressed_stream.str();

  // Return the compressed data.
  return std::vector<unsigned char>(
    compressed.begin(), 
    compressed.end()
  );
}
