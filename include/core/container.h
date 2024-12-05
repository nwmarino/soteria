//>==- container.h --------------------------------------------------------==<//
//
// This header declares the container class, which represents a container file
// instance. The container class is responsible for managing the container file
// and its contents.
//
//>==----------------------------------------------------------------------==<//

#ifndef SOTERIA_CONTAINER_H
#define SOTERIA_CONTAINER_H

#include <array>
#include <fstream>
#include <string>
#include <vector>

#include "fat.h"

namespace soteria {

class Container {
  /// The name of the container.
  const std::string name;

  /// The path to the container.
  const std::string path;

  /// The version of the container.
  std::array<unsigned char, 4> version;

  /// The salt used to hash the master password.
  mutable std::vector<unsigned char> salt;

  /// The hashed master password of the container.
  mutable std::vector<unsigned char> master;

  /// The derived encryption key.
  mutable std::array<unsigned char, 32> key;

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
            std::size_t size);

  /// Writes the version to the container.
  void store_version();

  /// Loads the version from the container.
  void load_version();

  /// Writes the current master hash to the container.
  void store_master();

  /// Loads the master hash from the container.
  void load_master();

public:
  ~Container();

  /// \returns A new container representation.
  /// \param path The path to the container.
  /// \param size The size of the container.
  static Container *create(const std::string &path, 
                           const std::string &pass, 
                           std::size_t size = 2048);

  /// \returns A pre-existing container representation.
  /// \param path The path to the container.
  static Container *open(const std::string &path, const std::string &pass);

  /// Writes the current state of the FAT to the container.
  void store_fat();

  /// Loads the current state of the FAT from the container.
  void load_fat();

  /// \returns `true` if this container contains a file with name \p name.
  bool contains(const std::string &name) const;

  /// \returns The FAT entry for the file with the name \p name.
  FATEntry &get_entry(const std::string &name) const;

  /// Stores a file to the container.
  /// \param in_path The path to the file to write.
  void store_file(const std::string &in_path);

  /// Loads a file from the container.
  /// \param out_path The path to write the file to.
  void load_file(const std::string &out_path);

  /// Attempts to delete file at \p path from the container and the FAT.
  /// \param path The path to the file to delete.
  /// \returns `true` if the deletion was successful.
  bool delete_file(const std::string &path); 

  /// Dumps the container's contents to \p path.
  /// \param path The path to dump the container to.
  void list(const std::string &path);

  /// \returns The FAT of this container.
  const std::vector<FATEntry> &get_fat() const { return fat; };
};

} // end namespace soteria

#endif // SOTERIA_CONTAINER_H
