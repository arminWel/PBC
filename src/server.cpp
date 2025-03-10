#include "server.h"
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/pk_algs.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <botan/x509_key.h>

#include <memory>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <string_view>
using json = nlohmann::json;
Server::Server() { this->db = json(); }

std::vector<uint8_t>
Server::register_user(std::string &username,
                      std::vector<uint8_t> &user_pub_key_view) {
  Botan::AutoSeeded_RNG rng;

  auto user_pub_key = Botan::X509::load_key(user_pub_key_view);
  if (user_pub_key->check_key(rng, true) == 0) {
    throw std::invalid_argument("User public key is malformed");
  }

  auto server_enc_key = create_private_key("RSA", rng);
  auto server_pub_key = server_enc_key->public_key();

  auto pw_view =
      std::string_view(this->db_password.data(), this->db_password.size());
  auto encoded_server_enc_key =
      Botan::PKCS8::BER_encode(*server_enc_key, rng, pw_view);
  auto encoded_user_pub_key = Botan::X509::BER_encode(*user_pub_key);

  this->add_user_entry_to_db(username, encoded_user_pub_key,
                             encoded_server_enc_key);

  return Botan::X509::BER_encode(*server_pub_key);
}

void Server::add_user_entry_to_db(std::string &username,
                                  std::vector<uint8_t> &user_pub_key,
                                  std::vector<uint8_t> &server_dec_key) {
  json exp = {{"user_pub_key", user_pub_key},
              {"server_dec_key", server_dec_key}};
  if (this->db.contains(username)) {
    throw std::invalid_argument("User already exists");
  }
  this->db[username] = exp;
}
