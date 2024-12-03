//>==- container.h --------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#ifndef SOTERIA_CONTAINER_H
#define SOTERIA_CONTAINER_H

#include <fstream>
#include <string>
#include <vector>

#include "fat.h"

namespace soteria {

/// Represents a container file instance.
class Container {
  /// The name of the container.
  const std::string name;

  /// The path to the container.
  const std::string path;

  /// The salt used to hash the master password.
  mutable std::vector<unsigned char> salt;

  /// The hashed master password of the container.
  mutable std::vector<unsigned char> master;

  /// The file stream for the container file.
  mutable std::fstream container;

  /// File allocation table.
  mutable std::vector<FATEntry> fat = {};

  /// Create a new container representation based on an existing container.
  /// \param path The path to the container.
  /// \param pass The password to the container (unmatched).
  Container(const std::string &path,
            const std::string &pass);

  /// Create a new container representation based on a new container.
  /// \param name The name of the container.
  /// \param path The path to the container.
  /// \param pass The password of the container.
  /// \param size The size of the container.
  Container(const std::string &name, 
            const std::string &path,
            const std::string &pass,
            std::size_t size = 1024);

public:
  ~Container();

  /// \returns A new container representation.
  /// \param path The path to the container.
  /// \param size The size of the container.
  static Container *create(const std::string &path, 
                           const std::string &pass, 
                           std::size_t size);

  /// \returns A pre-existing container representation.
  /// \param path The path to the container.
  static Container *open(const std::string &path, const std::string &pass);

  /// Writes the current master hash to the container.
  void store_master();

  /// Loads the master hash from the container.
  void load_master();

  /// Writes the current state of the FAT to the container.
  void store_fat();

  /// Loads the current state of the FAT from the container.
  void load_fat();

  /// Dumps the container's contents to \p path.
  /// \param path The path to dump the container to.
  void list(const std::string &path);
};

} // end namespace soteria

#endif // SOTERIA_CONTAINER_H
