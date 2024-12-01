//>==- cli.h --------------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#ifndef SOTERIA_CLI_H
#define SOTERIA_CLI_H

#include <string>

namespace soteria {

class cli {
public:
  [[noreturn]] static void fatal(const std::string &m);
};

} // end namespace soteria

#endif // SOTERIA_CLI_H
