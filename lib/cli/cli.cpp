//>==- cli.cpp ------------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#include <boost/program_options/options_description.hpp>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "boost/program_options.hpp"

#include "../../include/cli/cli.h"

namespace bpo = boost::program_options;

using namespace soteria;

[[nodiscard]] cli::CLIOpts cli::parse(int argc, char **argv) {
  CLIOpts opts;
  bpo::options_description desc("Options");
  desc.add_options()
    (
      "help,h", 
      "show help message"
    )
    (
      "make,mk", 
      bpo::value<std::string>(&opts.container), 
      "create a new container"
    )
    (
      "remove,rm", 
      bpo::value<std::string>(&opts.container), 
      "delete a container"
    )
    (
      "password,pw", 
      bpo::value<std::string>(&opts.password), 
      "specify the container password"
    )
    (
      "list,ls", 
      "log the contents of the container"
    )
    (
      "store", 
      bpo::value<std::vector<std::string>>(&opts.paths)->multitoken(), 
      "store files to the container"
    )
    (
      "load", 
      bpo::value<std::vector<std::string>>(&opts.paths)->multitoken(), 
      "load files from the container")
    (
      "log", 
      "log the container audit log to a file"
    );

  bpo::variables_map vmap;
  try {
    bpo::store(bpo::parse_command_line(argc, argv, desc), vmap);
    bpo::notify(vmap);

    // If help is requested, print the help message and exit.
    if (vmap.count("help")) {
      std::cout << desc << std::endl;
      exit(EXIT_SUCCESS);
    }

    // Enforce password requirement
    if (!vmap.count("password"))
      cli::fatal("err: password must be specified with -pw or --password");

    opts.password = vmap["password"].as<std::string>();

    // Ensure only one operation is given.
    unsigned int command_count = 0;

    if (vmap.count("make")) {
      command_count++;
      opts.command = Cmd::Make;
      opts.container = vmap["make"].as<std::string>();
    }

    if (vmap.count("remove")) {
      command_count++;
      opts.command = Cmd::Remove;
      opts.container = vmap["remove"].as<std::string>();
    }

    if (vmap.count("store")) {
      command_count++;
      opts.command = Cmd::Store;
      opts.paths = vmap["store"].as<std::vector<std::string>>();
    }
    if (vmap.count("load")) {
      command_count++;
      opts.command = Cmd::Load;
      opts.paths = vmap["load"].as<std::vector<std::string>>();
    }

    if (vmap.count("list")) {
      command_count++;
      opts.command = Cmd::List;
    }

    if (vmap.count("log")) {
      command_count++;
      opts.command = Cmd::Log;
    }

    if (command_count == 0)
      cli::fatal("err: no command specified");

    if (command_count > 1)
      cli::fatal("err: multiple commands specified");

  } catch (const bpo::error& ex) {
    std::cerr << "argument parsing error: " << ex.what() << std::endl;
    std::cout << desc << std::endl;
    exit(EXIT_FAILURE);
  } catch (const std::runtime_error& ex) {
    std::cerr << ex.what() << std::endl;
    std::cout << desc << std::endl;
    exit(EXIT_FAILURE);
  }

  return opts;
}

[[noreturn]] void cli::fatal(const std::string &m) {
  std::cerr << m << std::endl;
  std::exit(1);
}
