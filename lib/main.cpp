//>==- main.cpp -----------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#include <cstring>
#include <iostream>
#include <string>

#include "../include/cli/cli.h"
#include "../include/core/container.h"
#include "../include/encryption/aes.h"

using namespace soteria;

/// Skips to the next command line argument.
/// \param argc The number of arguments.
/// \param argv The argument vector.s
static void nextArg(int *argc, char ***argv) {
  if (*argc == 0)
    cli::fatal("missing argument");

  (*argc)--;
  (*argv)++;
}

int main(int argc, char **argv) {
  if (argc < 3)
    cli::fatal("usage: soteria <container> <operation> <file>...");

  // Skip the program name.
  nextArg(&argc, &argv);

  std::string container_name;
  bool make_new = false;
  bool op;

  // Read initial operations.
  if (strcmp("mk", argv[0]) == 0) {
    if (argc != 2)
      cli::fatal("usage: soteria mk <container>");

    nextArg(&argc, &argv);
    container_name = argv[0];
    make_new = true;  
  } else if (strcmp("rm", argv[0]) == 0) {
    if (argc != 2)
      cli::fatal("usage: soteria rm <container>");

    if (remove(argv[1]) != 0)
      cli::fatal("failed to delete container: " + std::string(argv[1]));

    return EXIT_SUCCESS;
  } else {
    if (argc < 2)
      cli::fatal("usage: soteria <container>");

    container_name = argv[0];
    nextArg(&argc, &argv);
  }

  // Create a new container if the execution requested it.
  if (make_new) {
    Container *container = Container::create(container_name, 1024);
    delete container;
    return EXIT_SUCCESS;
  }

  // Get the process operation.
  if (strcmp("load", argv[0]) == 0)
    op = 0;
  else if (strcmp("store", argv[0]) == 0)
    op = 1;
  else
    cli::fatal("unknown operation: " + std::string(argv[0]));

  // Skip the operation.
  nextArg(&argc, &argv);
  
  // Get the target file paths.
  std::vector<std::string> paths;
  while (argc > 0) {
    paths.push_back(argv[0]);
    nextArg(&argc, &argv);
  }

  // If no files given...
  if (paths.size() == 0) {
    cli::fatal(op ? "usage: soteria <container> load <file>..." 
                 : "usage: soteria <container> store <file>...");
  }

  std::vector<unsigned char> key = { 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64,
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64, 
    0x64,
    0x64,
    0x64,
  };

  // Open the container.
  Container *container = Container::open(container_name);

  // Perform the operation.
  if (op == 1) {
    for (const auto &path : paths)
      container->store_file(path, key);
  } else if (op == 0) {
    for (const auto &path : paths)
      container->load_file(path, key);
  } else
    cli::fatal("unknown operation");

  delete container;
  return EXIT_SUCCESS;
}
