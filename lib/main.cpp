//>==- main.cpp -----------------------------------------------------------==<//
//
//>==----------------------------------------------------------------------==<//

#include <algorithm>
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

  const std::string dec_out = "decrypted_" + std::string(argv[2]).substr(std::string(argv[2]).find_last_of('/') + 1);

  aes_decrypt_file(argv[2], dec_out, key);
  
  return 0;
}
