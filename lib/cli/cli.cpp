//>==- cli.cpp ------------------------------------------------------------==<//
//
// The following source implements the command line interface for the program.
//
//>==----------------------------------------------------------------------==<//

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "boost/program_options/options_description.hpp"
#include "boost/program_options/parsers.hpp"
#include "boost/program_options/positional_options.hpp"
#include "boost/program_options/variables_map.hpp"

#include "../../include/cli/cli.h"

namespace bpo = boost::program_options;

using namespace soteria;

[[nodiscard]] cli::CLIOpts cli::parse(int argc, char **argv) {
  // Define the command line options.
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

  // Add a positional option for the container path.
  bpo::options_description positional_desc("Positional options:");
  positional_desc.add_options()
    (
      "container",
      bpo::value<std::string>(&opts.container),
      "path to the container"
    );
  bpo::positional_options_description positional;
  positional.add("container", 1);

  // Parse the command line arguments.
  bpo::variables_map vmap;
  try {
    bpo::store(
      bpo::command_line_parser(argc, argv)
              .options(desc.add(positional_desc))
              .positional(positional)
              .run(),
      vmap
    );
    bpo::notify(vmap);

    // If help is requested, print the help message and exit.
    if (vmap.count("help")) {
      std::cout << desc << std::endl;
      exit(EXIT_SUCCESS);
    }

    // Enforce password requirement
    if (!vmap.count("password"))
      cli::fatal("[cli] password must be specified with --pw or --password");

    opts.password = vmap["password"].as<std::string>();

    // To ensure only one operation is given.
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
    
    // Check that a command was given.
    if (command_count == 0 && !vmap.count("container")) {
      cli::fatal("[cli] no container specified");
    } else if (command_count > 1) { // Check only one command was given.
      cli::fatal("[cli] multiple commands specified");
    } else if ((opts.command != Cmd::Make && opts.command != Cmd::Remove) 
        && !vmap.count("container")) { // Check a container path was given.
      cli::fatal("[cli] no container specified");
    }
  } catch (const bpo::error &ex) {
    std::cerr << "[cli] argument parsing error: " << ex.what() << std::endl;
    std::cout << desc << std::endl;
    exit(EXIT_FAILURE);
  } catch (const std::runtime_error &ex) {
    std::cerr << ex.what() << std::endl;
    std::cout << desc << std::endl;
    exit(EXIT_FAILURE);
  }

  return opts;
}

void cli::info(const std::string &m) noexcept
{ std::cerr << m << std::endl; }

[[noreturn]] void cli::fatal(const std::string &m) {
  std::cerr << m << std::endl;
  std::exit(EXIT_FAILURE);
}
