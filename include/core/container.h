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

  /// The file stream for the container file.
  mutable std::fstream container;

  /// File allocation table.
  mutable std::vector<FATEntry> fat;

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

  /// Writes data to the container.
  /// \param file_path The path to the file to write.
  /// \param data The data to write.
  void store_file(const std::string &in_path, const std::string &password);

  /// Attempts to read data from the container. Does not delete it.
  /// \param target_file The file to read from the container.
  void load_file(const std::string &out_path, const std::string &password);

  /// Writes the current state of the fat to the container.
  void write_fat();

  /// Reads the fat from the container.
  void read_fat();

  /// \returns The FAT of this container.
  const std::vector<FATEntry> &get_fat() const { return fat; }

  /// Stores the encryption key in the container.
  /// \param key The key to store.
  /// \param password The password to store the key with.
  void store_key(const std::vector<unsigned char> &key, 
                 const std::string &password);

  /// \returns The encryption key from the container.
  /// \param password The password to retrieve the key with.
  std::vector<unsigned char> load_key(const std::string &password);

  /// Changes the master password of the container.
  /// \param old_pass The old password.
  /// \param new_pass The new password.
  void change_master(const std::string &old_pass, const std::string &new_pass);

  /// \returns The end offset of the container.
  std::size_t end_offset() const;
};

} // end namespace soteria

#endif // SOTERIA_CONTAINER_H
