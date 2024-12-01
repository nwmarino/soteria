//>==- container.h --------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#ifndef SOTERIA_CONTAINER_H
#define SOTERIA_CONTAINER_H

#include <fstream>
#include <string>
#include <vector>

namespace soteria {

class Container {
  /// The name of the container.
  const std::string name;

  /// The path to the container.
  const std::string path;

  /// The file stream for the container file.
  std::fstream container;

  /// Private constructor for pre-existing container representation.
  /// \param path The path to the container.
  Container(const std::string &path);

  /// Private constructor for new container representation.
  /// \param name The name of the container.
  /// \param path The path to the container.
  /// \param size The size of the container.
  Container(const std::string &name, const std::string &path, std::size_t size);
  
public:
  ~Container();

  /// \returns A new container representation.
  /// \param path The path to the container.
  /// \param size The size of the container.
  static Container *create(const std::string &path, std::size_t size);

  /// \returns A pre-existing container representation.
  /// \param path The path to the container.
  static Container *open(const std::string &path);

  /// Writes data to the container.
  /// \param file_path The path to the file to write.
  /// \param data The data to write.
  void store_file(const std::string &in_path,
                  const std::vector<unsigned char> &key);

  /// Attempts to read data from the container. Does not delete it.
  /// \param target_file The file to read from the container.
  void load_file(const std::string &out_path,
                 const std::vector<unsigned char> &key);
};

} // end namespace soteria

#endif // SOTERIA_CONTAINER_H
