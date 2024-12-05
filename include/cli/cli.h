//>==- cli.h --------------------------------------------------------------==<//
//
// This header file declares a CLI interface to parse command line arguments
// and raise errors with.
//
//>==----------------------------------------------------------------------==<//

#ifndef SOTERIA_CLI_H
#define SOTERIA_CLI_H

#include <string>
#include <vector>

namespace soteria {

class cli {
public:
  /// Possible execution commands.
  enum class Cmd {
    Make = 0,
    Remove,
    Store,
    Load,
    List,
    Log,
  };

  /// Represents parsed CLI arguments.
  struct CLIOpts {
    std::string container;
    std::string password;
    Cmd command;
    std::vector<std::string> paths;
  };

  /// \returns A struct of parsed CLI arguments.
  /// \param argc The number of arguments.
  /// \param argv The argument vector.
  [[nodiscard]] static CLIOpts parse(int argc, char **argv);

  /// Quits the program with an error message \p m.
  [[noreturn]] static void fatal(const std::string &m);
};

} // end namespace soteria

#endif // SOTERIA_CLI_H
