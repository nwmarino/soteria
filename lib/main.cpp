//>==- main.cpp -----------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#include <string>

#include "../include/cli/cli.h"
#include "../include/encryption/aes.h"

using namespace soteria;

int main(int argc, char *argv[]) {
  if (argc != 3)
    cli::fatal("expected 2 arguments, got " + std::to_string(argc - 1));
  
  std::vector<unsigned char> key, iv;
  generate_key_iv(key, iv);

  aes_encrypt_file(argv[1], argv[2], key, iv);
  
  return 0;
}
