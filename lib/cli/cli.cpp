//>==- cli.cpp ------------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#include <cstdlib>
#include <iostream>
#include <string>

#include "../../include/cli/cli.h"

using namespace soteria;

[[noreturn]] void cli::fatal(const std::string &m) {
  std::cerr << m << std::endl;
  std::exit(1);
}
