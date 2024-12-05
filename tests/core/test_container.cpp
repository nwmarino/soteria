#include "boost/filesystem/operations.hpp"
#include "catch2/catch_test_macros.hpp"
#include "catch2/generators/catch_generators.hpp"

#include "../../include/core/container.h"

namespace fs = boost::filesystem;

using namespace soteria;

TEST_CASE("Container Creation", "[container]") {
  int SIZE = GENERATE(1024, 2048, 4096);

  Container *container_c = Container::create("test", "password", SIZE);
  delete container_c;

  REQUIRE(fs::exists("test"));
  REQUIRE(fs::file_size("test") == SIZE);
  fs::remove("test");
}

TEST_CASE("Container Opening", "[container]") {
  Container *container_c = Container::create("test", "password");
  delete container_c;
  REQUIRE(fs::exists("test"));

  Container *container_o = Container::open("test", "password");
  delete container_o;

  REQUIRE(fs::exists("test"));
  fs::remove("test");
}

TEST_CASE("Container Empty FAT persistence", "[container]") {
  Container *container_c = Container::create("test", "password");
  const std::vector<FATEntry> fat_c = container_c->get_fat();
  delete container_c;

  Container *container_o = Container::open("test", "password");
  container_o->load_fat();
  const std::vector<FATEntry> fat_o = container_o->get_fat();
  delete container_o;
  
  REQUIRE(fat_c.empty());
  REQUIRE(fat_o.empty());
  REQUIRE(fat_c.size() == fat_o.size());

  for (const FATEntry &entry : fat_c) {
    auto it = std::find_if(
      fat_o.begin(),
      fat_o.end(),
      [&entry](const FATEntry &e) -> bool {
        return e.filename == entry.filename;
      }
    );
    REQUIRE(it != fat_o.end());
  }

  REQUIRE(fs::exists("test"));
  fs::remove("test");
}

TEST_CASE("Container file storing", "[container]") {
  Container *container = Container::create("test", "password", 1024);

  std::ofstream file("test_file");
  REQUIRE(fs::exists("test_file"));
  file << "test";
  container->store_file("test_file");
  fs::remove("test_file");

  // One block size since the file is 4 bytes, 12 byte padding.
  REQUIRE(fs::file_size("test") == 1024);
  delete container;
  fs::remove("test");
}

TEST_CASE("Container file loading", "[container]") {
  Container *container_c = Container::create("test", "password");
  delete container_c;

  Container *container_o = Container::open("test", "password");

  std::ofstream input_file("test_file");
  REQUIRE(fs::exists("test_file"));
  input_file << "test";
  input_file.close();

  container_o->store_file("test_file");
  fs::remove("test_file");
  container_o->load_file("test_file");

  // Check that test_file contains "test"
  REQUIRE(fs::exists("test_file"));
  std::ifstream out_file("test_file");
  std::string content;
  out_file >> content;
  out_file.close();

  REQUIRE(content == "test");
  delete container_o;
  fs::remove("test_file");
  fs::remove("test");
}

TEST_CASE("Container file deletion", "[container]") {
  Container *container_c = Container::create("test", "password");
  delete container_c;

  Container *container_o = Container::open("test", "password");

  std::ofstream input_file("test_file");
  REQUIRE(fs::exists("test_file"));
  input_file << "test";
  input_file.close();

  container_o->store_file("test_file");
  fs::remove("test_file");
  REQUIRE(!container_o->get_fat().empty());

  container_o->delete_file("test_file");

  REQUIRE(!fs::exists("test_file"));
  REQUIRE(container_o->get_fat().empty());

  delete container_o;
  fs::remove("test");
}
