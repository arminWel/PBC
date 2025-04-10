#include "common.h"
#include "server.h"
#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/hex.h>
#include <botan/pkcs8.h>
#include <botan/rsa.h>
#include <botan/secmem.h>
#include <botan/x509_key.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <vector>
using json = nlohmann::json;

class ServerTest : public Server {
public:
  ServerTest() : Server(Botan::secure_vector<char>{'p', 'w'}) {}
  void pub_add_user_entry_to_db(std::string &username,
                                std::string &user_pub_key,
                                std::string &server_dec_key) {
    this->add_user_entry_to_db(username, user_pub_key, server_dec_key);
  }
  json get_db() { return this->db; }
  Botan::secure_vector<char> get_db_password() { return this->db_password; }
};

class ServerDatabaseFixture : public ::testing::Test {
protected:
  ServerTest server;
  std::string username = "test_user";
  std::string user_key = {0, 1};
  std::string server_key = {2, 3};
};

TEST_F(ServerDatabaseFixture, DatabaseIsEmpty) {
  EXPECT_TRUE(server.get_db().empty());
}

TEST_F(ServerDatabaseFixture, DatabaseContainsNewEntry) {
  server.pub_add_user_entry_to_db(username, user_key, server_key);
  json new_entry = {{"user_pub_key", user_key}, {"server_dec_key", server_key}};
  EXPECT_EQ(server.get_db()[username], new_entry);
}

TEST_F(ServerDatabaseFixture, SettingNameTwiceIsIllegal) {
  server.pub_add_user_entry_to_db(username, user_key, server_key);
  EXPECT_THROW(server.pub_add_user_entry_to_db(username, user_key, server_key),
               std::invalid_argument);
}

class ServerRegistrationFixture : public ::testing::Test {
protected:
  Botan::AutoSeeded_RNG rng;
  const Botan::EC_Group group = Botan::EC_Group::from_name("secp521r1");
  Botan::ECDSA_PrivateKey key{rng, group};
  std::string user_pub_key = Botan::X509::PEM_encode(*key.public_key());
  ServerTest server;
  std::string username = "test_user";
};

TEST_F(ServerRegistrationFixture, RegisterUserSuccessfully) {
  auto server_pub_key_view = server.register_user(username, user_pub_key);
  EXPECT_EQ(server.get_db()[username]["user_pub_key"], user_pub_key);

  auto server_pub_key = PBC::load_key(server_pub_key_view);
  EXPECT_TRUE(server_pub_key->check_key(rng, true));

  auto database = server.get_db();
  const std::vector<uint8_t> server_dec_key_view =
      database[username]["server_dec_key"];

  auto pw = server.get_db_password();
  std::string pw_view(pw.begin(), pw.end());
  auto server_dec_key = Botan::PKCS8::load_key(server_dec_key_view, pw_view);

  EXPECT_EQ(server_dec_key->public_key()->public_key_bits(),
            server_pub_key->public_key_bits());
}

TEST_F(ServerRegistrationFixture, RegisterUserWithMalformedKey) {
  std::string malformed_key = {0x00}; // Invalid key
  EXPECT_THROW(server.register_user(username, malformed_key),
               std::invalid_argument);
  EXPECT_FALSE(server.get_db().contains(username));
}

TEST_F(ServerRegistrationFixture, RegisterUserWithDuplicateUsername) {
  server.register_user(username, user_pub_key);
  Botan::ECDSA_PrivateKey key_new(rng, group);
  auto user_pub_key_new = Botan::X509::PEM_encode(*key_new.public_key());
  EXPECT_NE(user_pub_key_new, user_pub_key);

  EXPECT_THROW(server.register_user(username, user_pub_key),
               std::invalid_argument);
  EXPECT_EQ(server.get_db()[username]["user_pub_key"], user_pub_key);
}

TEST_F(ServerRegistrationFixture, RegisterMultipleUsers) {
  server.register_user(username, user_pub_key);
  EXPECT_NO_THROW(server.register_user("test_user2", user_pub_key));
}
