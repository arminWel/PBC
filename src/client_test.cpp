#include "client.h"
#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/pubkey.h>
#include <botan/secmem.h>
#include <botan/x509_key.h>
#include <catch2/catch_test_macros.hpp>
#include <memory>
#include <vector>

class ClientTest : public Client {
public:
  ClientTest(const std::string &username) : Client(username) {}
  ClientTest(const std::vector<uint8_t> &server_enc_key,
             const std::string &username)
      : Client(server_enc_key, username) {}

  // Expose protected members for testing
  using Client::key_rng;
  using Client::server_enc_key;
  using Client::username;

  // Expose the password for testing
  Botan::secure_vector<uint8_t> pw = {'t', 'e', 's', 't', 'p', 'a', 's', 's'};

  // Override virtual method to provide test password
  Botan::secure_vector<uint8_t> get_pw() override { return this->pw; }

  // Expose protected methods for testing
  std::unique_ptr<Botan::HMAC_DRBG>
  pub_get_rng_explicit_rand(const Botan::secure_vector<uint8_t> &key_rng) {
    return get_rng_explicit_rand(key_rng);
  }

  std::unique_ptr<Botan::ECDSA_PrivateKey>
  pub_get_sign_sk(const Botan::secure_vector<uint8_t> &key_rng) {
    return get_sign_sk(key_rng);
  }
};

TEST_CASE("Client initialization", "[client]") {
  std::string username = "test_user";

  SECTION("Initialize client with username only") {
    ClientTest client(username);
    REQUIRE(client.username == username);
    REQUIRE(client.key_rng.empty());
  }

  SECTION("Initialize client with username and server key") {
    std::vector<uint8_t> server_key = {0, 1, 2, 3, 4};
    ClientTest client(server_key, username);
    REQUIRE(client.username == username);
    REQUIRE(client.server_enc_key == server_key);
    REQUIRE(client.key_rng.empty());
  }
}

TEST_CASE("Client key generation", "[client][keys]") {
  ClientTest client("test_user");
  Botan::AutoSeeded_RNG rng;
  Botan::secure_vector<uint8_t> test_key(BOTAN_RNG_RESEED_POLL_BITS);
  rng.randomize(test_key.data(), test_key.size());

  SECTION("RNG generation works with seed") {
    auto drbg = client.pub_get_rng_explicit_rand(test_key);
    REQUIRE(drbg != nullptr);

    // Verify RNG produces output
    std::vector<uint8_t> random_data(16);
    REQUIRE(drbg->is_seeded());
    drbg->randomize(random_data.data(), random_data.size());

    // Verify that we get the same output with the same seed
    auto drbg2 = client.pub_get_rng_explicit_rand(test_key);
    std::vector<uint8_t> random_data2(16);
    drbg2->randomize(random_data2.data(), random_data2.size());

    REQUIRE(random_data == random_data2);
  }
  SECTION("RNG generation differs with different inputs") {
    auto drbg = client.pub_get_rng_explicit_rand(test_key);
    REQUIRE(drbg != nullptr);

    // Verify RNG produces output
    std::vector<uint8_t> random_data(16);
    REQUIRE(drbg->is_seeded());
    drbg->randomize(random_data.data(), random_data.size());

    SECTION("RNG generation differs with differnt Passwords") {
      // Verify that we get the same output with the same seed
      client.pw[0]++;
      auto drbg2 = client.pub_get_rng_explicit_rand(test_key);
      std::vector<uint8_t> random_data2(16);
      drbg2->randomize(random_data2.data(), random_data2.size());

      REQUIRE(random_data != random_data2);
    }
    SECTION("RNG generation differs with different Seeds") {
      // Verify that we get the same output with the same seed
      test_key[0]++;
      auto drbg2 = client.pub_get_rng_explicit_rand(test_key);
      std::vector<uint8_t> random_data2(16);
      drbg2->randomize(random_data2.data(), random_data2.size());

      REQUIRE(random_data != random_data2);
    }
  }

  SECTION("Signing key generation works") {
    auto signing_key = client.pub_get_sign_sk(test_key);
    REQUIRE(signing_key != nullptr);

    // Verify key is valid
    REQUIRE(signing_key->check_key(rng, true));

    // Verify key is deterministic based on seed
    auto signing_key2 = client.pub_get_sign_sk(test_key);
    REQUIRE(signing_key->private_value() == signing_key2->private_value());

    test_key[0]++;
    signing_key2 = client.pub_get_sign_sk(test_key);
    REQUIRE(signing_key->private_value() != signing_key2->private_value());
  }
}

TEST_CASE("Client registration process", "[client][registration]") {
  ClientTest client("test_user");

  SECTION("Registration stage 1 generates public key") {
    auto pub_key = client.register_stage_1();
    REQUIRE_FALSE(pub_key.empty());
    REQUIRE_FALSE(client.key_rng.empty());

    // Verify pub_key is a valid public key
    std::unique_ptr<Botan::Public_Key> loaded_key;
    REQUIRE_NOTHROW(loaded_key = Botan::X509::load_key(pub_key));

    Botan::AutoSeeded_RNG rng;
    REQUIRE(loaded_key->check_key(rng, true));
  }

  SECTION("Registration stage 2 stores server key") {
    std::vector<uint8_t> server_key = {0, 1, 2, 3, 4, 5};
    client.register_stage_2(server_key);
    REQUIRE(client.server_enc_key == server_key);
  }

  SECTION("Full registration flow") {
    // Stage 1: client generates key pair and sends public key
    auto pub_key = client.register_stage_1();
    REQUIRE_FALSE(client.key_rng.empty());

    // Stage 2: client receives server public key
    std::vector<uint8_t> server_key = {0, 1, 2, 3, 4, 5};
    client.register_stage_2(server_key);
    REQUIRE(client.server_enc_key == server_key);
  }
}
