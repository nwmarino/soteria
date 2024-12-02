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

  switch (opts.command) {
  case cli::Cmd::Make:
    Container::create(opts.container, opts.password, 1024);
    return EXIT_SUCCESS;
  case cli::Cmd::Remove:
    /// TODO: password-protect deletion
    if (!fs::exists(opts.container))
      cli::fatal("container does not exist");

    fs::remove(opts.container.c_str());
    return EXIT_SUCCESS;
  case cli::Cmd::Store:
    break;
  case cli::Cmd::Load:
    break;
  case cli::Cmd::List:
    break;
  case cli::Cmd::Log:
    break;
  }

  return EXIT_SUCCESS;
}
