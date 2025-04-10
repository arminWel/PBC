#include "client.h"
#include "common.h"
#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/pk_algs.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/secmem.h>
#include <botan/x509_key.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

class ClientTest : public Client {
public:
  ClientTest(const std::string &username) : Client(username) {}
  ClientTest(const std::string &server_enc_key, const std::string &username)
      : Client(server_enc_key, username) {}

  using Client::key_rng;
  using Client::server_enc_key;
  using Client::username;

  Botan::secure_vector<uint8_t> pw = {'t', 'e', 's', 't', 'p', 'a', 's', 's'};

  Botan::secure_vector<uint8_t> get_pw() override { return this->pw; }

  std::unique_ptr<Botan::HMAC_DRBG>
  pub_get_rng_explicit_rand(const Botan::secure_vector<uint8_t> &key_rng) {
    return get_rng_explicit_rand(key_rng);
  }

  std::unique_ptr<Botan::ECDSA_PrivateKey>
  pub_get_sign_sk(const Botan::secure_vector<uint8_t> &key_rng) {
    return get_sign_sk(key_rng);
  }
};

class ClientInitializationFixture : public ::testing::Test {
protected:
  std::string username = "test_user";
};

TEST_F(ClientInitializationFixture, InitializeWithUsernameOnly) {
  ClientTest client(username);
  EXPECT_EQ(client.username, username);
  EXPECT_TRUE(client.key_rng.empty());
}

TEST_F(ClientInitializationFixture, InitializeWithUsernameAndServerKey) {
  std::string server_key = {0, 1, 2, 3, 4};
  ClientTest client(server_key, username);
  EXPECT_EQ(client.username, username);
  EXPECT_EQ(client.server_enc_key, server_key);
  EXPECT_TRUE(client.key_rng.empty());
}

class ClientKeyGenerationFixture : public ::testing::Test {
protected:
  ClientTest client{"test_user"};
  Botan::AutoSeeded_RNG rng;
  Botan::secure_vector<uint8_t> test_key;

  void SetUp() override {
    test_key.resize(BOTAN_RNG_RESEED_POLL_BITS);
    rng.randomize(test_key.data(), test_key.size());
  }
};

TEST_F(ClientKeyGenerationFixture, RNGGenerationWithSeed) {
  auto drbg = client.pub_get_rng_explicit_rand(test_key);
  ASSERT_NE(drbg, nullptr);

  std::vector<uint8_t> random_data(16);
  EXPECT_TRUE(drbg->is_seeded());
  drbg->randomize(random_data.data(), random_data.size());

  auto drbg2 = client.pub_get_rng_explicit_rand(test_key);
  std::vector<uint8_t> random_data2(16);
  drbg2->randomize(random_data2.data(), random_data2.size());

  EXPECT_EQ(random_data, random_data2);
}

TEST_F(ClientKeyGenerationFixture, RNGGenerationDiffersWithDifferentPasswords) {
  auto drbg = client.pub_get_rng_explicit_rand(test_key);
  ASSERT_NE(drbg, nullptr);

  std::vector<uint8_t> random_data(16);
  EXPECT_TRUE(drbg->is_seeded());
  drbg->randomize(random_data.data(), random_data.size());

  client.pw[0]++;
  auto drbg2 = client.pub_get_rng_explicit_rand(test_key);
  std::vector<uint8_t> random_data2(16);
  drbg2->randomize(random_data2.data(), random_data2.size());

  EXPECT_NE(random_data, random_data2);
}

TEST_F(ClientKeyGenerationFixture, RNGGenerationDiffersWithDifferentSeeds) {
  auto drbg = client.pub_get_rng_explicit_rand(test_key);
  ASSERT_NE(drbg, nullptr);

  std::vector<uint8_t> random_data(16);
  EXPECT_TRUE(drbg->is_seeded());
  drbg->randomize(random_data.data(), random_data.size());

  test_key[0]++;
  auto drbg2 = client.pub_get_rng_explicit_rand(test_key);
  std::vector<uint8_t> random_data2(16);
  drbg2->randomize(random_data2.data(), random_data2.size());

  EXPECT_NE(random_data, random_data2);
}

TEST_F(ClientKeyGenerationFixture, SigningKeyGenerationWorks) {
  auto signing_key = client.pub_get_sign_sk(test_key);
  ASSERT_NE(signing_key, nullptr);

  EXPECT_TRUE(signing_key->check_key(rng, true));

  auto signing_key2 = client.pub_get_sign_sk(test_key);
  EXPECT_EQ(signing_key->private_value(), signing_key2->private_value());

  test_key[0]++;
  signing_key2 = client.pub_get_sign_sk(test_key);
  EXPECT_NE(signing_key->private_value(), signing_key2->private_value());
}

class ClientRegistrationFixture : public ::testing::Test {
protected:
  ClientTest client{"test_user"};
  Botan::AutoSeeded_RNG rng;
  std::string serialized_enc_key;

  void SetUp() override {
    auto enc_key = Botan::create_private_key("RSA", rng);
    serialized_enc_key = Botan::X509::PEM_encode(*enc_key->public_key());
  }
};

TEST_F(ClientRegistrationFixture, RegistrationStage1FailsWithInvalidUsername) {
  ClientTest invalid_client("");
  EXPECT_THROW(invalid_client.register_stage_1(), std::invalid_argument);
}

TEST_F(ClientRegistrationFixture, RegistrationStage1GeneratesPublicKey) {
  auto pub_key = client.register_stage_1();
  EXPECT_FALSE(pub_key.empty());
  EXPECT_FALSE(client.key_rng.empty());

  std::unique_ptr<Botan::Public_Key> loaded_key;
  loaded_key = PBC::load_key(pub_key);

  EXPECT_TRUE(loaded_key->check_key(rng, true));
}

TEST_F(ClientRegistrationFixture, RegistrationStage2FailsWithInvalidServerKey) {
  std::string invalid_server_key = {};
  EXPECT_THROW(client.register_stage_2(invalid_server_key),
               std::invalid_argument);
}

TEST_F(ClientRegistrationFixture,
       RegistrationStage2SucceedsWithValidServerKey) {
  client.register_stage_2(serialized_enc_key);
  EXPECT_EQ(client.server_enc_key, serialized_enc_key);
}

TEST_F(ClientRegistrationFixture, FullRegistrationFlow) {
  auto pub_key = client.register_stage_1();
  EXPECT_FALSE(client.key_rng.empty());

  client.register_stage_2(serialized_enc_key);
  EXPECT_EQ(client.server_enc_key, serialized_enc_key);
}
