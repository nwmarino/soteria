//>==- main.cpp -----------------------------------------------------------==<//
//
// The following source drives the CLI interface and container operations.
//
//>==----------------------------------------------------------------------==<//

#include <string>

#include "boost/filesystem/operations.hpp"

#include "../include/cli/cli.h"
#include "../include/core/container.h"

namespace fs = boost::filesystem;

using namespace soteria;

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
      cli::fatal("[soteria] container does not exist: " + opts.container);

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
    container->list(opts.container.substr(
      opts.container.find_last_of('/') + 1) + "_ls.txt"
    );
  }

  if (opts.command == cli::Cmd::Log) {

  }

  delete container;
  return EXIT_SUCCESS;
}
