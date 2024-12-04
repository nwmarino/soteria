#define CATCH_CONFIG_MAIN
#include "catch2/catch_test_macros.hpp"
#include "catch2/catch_session.hpp"

#include <fstream>
#include <vector>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include "../../include/utils/encryption.h"

using namespace soteria;

TEST_CASE("Basic Encryption", "[aes]") {
  std::array<unsigned char, 32> key = generate_key();
  std::array<unsigned char, 16> iv = generate_iv();
  std::vector<unsigned char> input_data = {'T', 'e', 's', 't'};
  std::vector<unsigned char> encrypted_data;
  std::vector<unsigned char> decrypted_data;

  // Run encryption and ensure it did something.
  encrypted_data = aes_encrypt(input_data, key, iv);
  REQUIRE(encrypted_data != input_data);

  // Run decryption and ensure the decrypted data matches the input data.
  decrypted_data = aes_decrypt(encrypted_data, key, iv);
  REQUIRE(decrypted_data == input_data);
}

TEST_CASE("Random Generation", "[aes]") {
  std::vector<unsigned char> rand_data = generate_rand(64);
  REQUIRE(rand_data.size() == 64);
}

TEST_CASE("Checksum Generation", "[aes]") {
  std::ofstream file("test.txt");
  file << "Test";
  file.close();
  std::array<unsigned char, 32> checksum = compute_checksum("test.txt");
  REQUIRE(checksum.size() == 32);

  std::remove("test.txt");
}

int main(int argc, char* argv[]) {
  Catch::Session session;
  return session.run(argc, argv);
}
