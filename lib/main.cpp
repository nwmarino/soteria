//>==- main.cpp -----------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#include <cstring>
#include <string>

#include "boost/filesystem.hpp"

#include "../include/cli/cli.h"
#include "../include/core/container.h"
#include "../include/utils/encryption.h"

namespace fs = boost::filesystem;

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
  cli::CLIOpts opts = cli::parse(argc, argv);

  if (opts.command == cli::Cmd::Make) {
    Container *container = Container::create(
      opts.container, 
      opts.password
    );
    delete container;
    return EXIT_SUCCESS;
  } else if (opts.command == cli::Cmd::Remove) {
    if (!fs::exists(opts.container))
      cli::fatal("container does not exist");

    fs::remove(opts.container.c_str());
    return EXIT_SUCCESS;
  }

  Container *container = Container::open(
    opts.container, 
    opts.password
  );

  if (opts.command == cli::Cmd::Store) {
    for (std::string &path : opts.paths)
      container->store_file(path);
  }

  if (opts.command == cli::Cmd::Load) {
    for (std::string &path : opts.paths)
      container->load_file(path);
  }

  if (opts.command == cli::Cmd::List) {
    container->list("./list.txt");
  }

  if (opts.command == cli::Cmd::Log) {

  }

  delete container;
  return EXIT_SUCCESS;
}
