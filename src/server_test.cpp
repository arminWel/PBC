#include "server.h"
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/pkcs8.h>
#include <botan/rsa.h>
#include <botan/x509_key.h>
#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

class ServerTest : public Server {
public:
  ServerTest() : Server() {}
  void pub_add_user_entry_to_db(std::string &username,
                                std::vector<uint8_t> &user_pub_key,
                                std::vector<uint8_t> &server_dec_key) {
    this->add_user_entry_to_db(username, user_pub_key, server_dec_key);
  }
  json get_db() { return this->db; }
};

TEST_CASE("Server has working database", "[database]") {
  ServerTest server;
  std::string username = "test_user";
  std::vector<uint8_t> user_key = {0, 1};
  std::vector<uint8_t> server_key = {2, 3};

  SECTION("Database is empty") { REQUIRE(server.get_db().empty()); }

  SECTION("Database contains new entry") {
    server.pub_add_user_entry_to_db(username, user_key, server_key);
    json new_entry = {{"user_pub_key", user_key},
                      {"server_dec_key", server_key}};
    REQUIRE(server.get_db()[username] == new_entry);
  }

  SECTION("Setting name twice is illegal") {
    server.pub_add_user_entry_to_db(username, user_key, server_key);
    json new_entry = {{"user_pub_key", user_key},
                      {"server_dec_key", server_key}};
    REQUIRE_THROWS_AS(
        server.pub_add_user_entry_to_db(username, user_key, server_key),
        std::invalid_argument);
  }
}
