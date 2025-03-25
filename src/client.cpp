#include "client.h"
#include <botan/auto_rng.h>
#include <botan/ecdsa.h>
#include <botan/hmac_drbg.h>
#include <botan/secmem.h>
#include <botan/x509_key.h>
#include <memory>
#include <vector>

Client::Client(const std::string &username) : username(username) {};
Client::Client(const std::vector<uint8_t> &server_enc_key,
               const std::string &username)
    : server_enc_key(server_enc_key), username(username) {};

std::unique_ptr<Botan::HMAC_DRBG>
Client::get_rng_explicit_rand(const Botan::secure_vector<uint8_t> &key) {
  auto hmac =
      Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
  hmac->set_key(key);
  auto rng_exp_rand = std::make_unique<Botan::HMAC_DRBG>(std::move(hmac));
  rng_exp_rand->add_entropy(this->get_pw());

  return rng_exp_rand;
};

std::unique_ptr<Botan::ECDSA_PrivateKey>
Client::get_sign_sk(const Botan::secure_vector<uint8_t> &key) {
  auto rng_exp_rand = this->get_rng_explicit_rand(key);

  const auto group = Botan::EC_Group::from_name("secp521r1");
  auto sign_sk =
      std::make_unique<Botan::ECDSA_PrivateKey>(*rng_exp_rand, group);
  return sign_sk;
};

std::vector<uint8_t> Client::register_stage_1() {
  Botan::AutoSeeded_RNG rng;
  Botan::secure_vector<uint8_t> key_k;
  size_t key_length = BOTAN_RNG_RESEED_POLL_BITS;
  rng.randomize(key_k.data(), key_length);

  auto sign_sk = this->get_sign_sk(key_k);

  this->key_k = key_k;
  return Botan::X509::BER_encode(*sign_sk->public_key());
};

void Client::register_stage_2(const std::vector<uint8_t> &server_enc_key) {
  this->server_enc_key = server_enc_key;
};
