#include "server.h"
#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/hex.h>
#include <botan/pkcs8.h>
#include <botan/rsa.h>
#include <botan/secmem.h>
#include <botan/x509_key.h>
#include <catch2/catch_test_macros.hpp>
#include <iostream>
#include <nlohmann/json.hpp>
#include <vector>
using json = nlohmann::json;

class ServerTest : public Server {
public:
  ServerTest() : Server(Botan::secure_vector<char>{'p', 'w'}) {}
  void pub_add_user_entry_to_db(std::string &username,
                                std::vector<uint8_t> &user_pub_key,
                                std::vector<uint8_t> &server_dec_key) {
    this->add_user_entry_to_db(username, user_pub_key, server_dec_key);
  }
  json get_db() { return this->db; }
  Botan::secure_vector<char> get_db_password() { return this->db_password; }
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
TEST_CASE("Server registration function", "[register_user]") {
  Botan::AutoSeeded_RNG rng;
  const auto group = Botan::EC_Group::from_name("secp521r1");
  Botan::ECDSA_PrivateKey key(rng, group);
  auto user_pub_key = Botan::X509::BER_encode(*key.public_key());

  ServerTest server;
  std::string username = "test_user";

  SECTION("Register user successfully") {
    auto server_pub_key_view = server.register_user(username, user_pub_key);
    REQUIRE(server.get_db()[username]["user_pub_key"] == user_pub_key);
    auto server_pub_key = Botan::X509::load_key(server_pub_key_view);
    REQUIRE(server_pub_key->check_key(rng, true));

    auto database = server.get_db();
    const std::vector<uint8_t> server_dec_key_view =
        database[username]["server_dec_key"];

    auto pw = server.get_db_password();
    std::string pw_view(pw.begin(), pw.end());
    auto server_dec_key = Botan::PKCS8::load_key(server_dec_key_view, pw_view);

    REQUIRE(server_dec_key->public_key()->public_key_bits() ==
            server_pub_key->public_key_bits());
  }

  SECTION("Register user with malformed key") {
    std::vector<uint8_t> malformed_key = {0x00}; // Invalid key
    REQUIRE_THROWS_AS(server.register_user(username, malformed_key),
                      std::invalid_argument);
    REQUIRE_FALSE(server.get_db().contains(username));
  }

  SECTION("Register user with duplicate username") {
    server.register_user(username, user_pub_key);
    Botan::ECDSA_PrivateKey key_new(rng, group);
    auto user_pub_key_new = Botan::X509::BER_encode(*key_new.public_key());
    REQUIRE_FALSE(user_pub_key_new == user_pub_key);

    REQUIRE_THROWS_AS(server.register_user(username, user_pub_key),
                      std::invalid_argument);
    REQUIRE(server.get_db()[username]["user_pub_key"] == user_pub_key);
  }
  SECTION("Register multiple users") {
    server.register_user(username, user_pub_key);
    REQUIRE_NOTHROW(server.register_user("test_user2", user_pub_key));
  }
}
