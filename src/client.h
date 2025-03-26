#ifndef pbc_client
#define pbc_client
#include <botan/ecdsa.h>
#include <botan/hmac_drbg.h>
#include <botan/secmem.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <vector>
using json = nlohmann::json;

class Client {
public:
  Client(const std::string &username);
  /**
   * @brief Construct a new Client object
   *
   * @param key_k Derandomized seed for the derivation of the signature key
   * pair.
   * @param server_enc_key The public encryption key of the server.
   * @param username The username of the client.
   * @return Client object.
   */
  Client(const std::vector<uint8_t> &server_enc_key,
         const std::string &username);
  /**
   * @brief First stage of the registration process. Generates a seed key_k,
   * saves it, and, using the password, derives a signature key pair. The public
   * part of it is the return value.
   * @return serialized public signature key.
   */
  std::vector<uint8_t> register_stage_1();
  /**
   * @brief Second stage of the registration process. Accepts the serialized
   * server encryption key saves it.
   *
   * @param server_enc_key X509 encoded public encryption key of the server.
   * Sets this->server_enc_key
   *
   */
  void register_stage_2(const std::vector<uint8_t> &server_enc_key);

protected:
  /**
   * @brief This function should return the user password. It must be
   * implemented by the derived class.
   * @return Botan::secure_vector<uint8_t> The user password.
   */
  virtual Botan::secure_vector<uint8_t> get_pw() = 0;
  /**
   * @brief Create a RNG with @p key as the seed, that
   * directly reads in the password using the get_pw()
   * function.
   *
   * @param key_mac Seed for the MAC
   * @param key_rng Seed for the RNG
   * @return The seeded RNG.
   */
  std::unique_ptr<Botan::HMAC_DRBG>
  get_rng_explicit_rand(const Botan::secure_vector<uint8_t> &key_mac,
                        const Botan::secure_vector<uint8_t> &key_rng);

  /**
   * @brief Get a private signing key depending on @p key and
   * the password from get_pw()
   *
   *
   * @param key_mac Seed for the MAC
   * @param key_rng The key, with which the rng is seeded
   *
   * @return The private signing key
   */
  std::unique_ptr<Botan::ECDSA_PrivateKey>
  get_sign_sk(const Botan::secure_vector<uint8_t> &key_mac,
              const Botan::secure_vector<uint8_t> &key_rng);
  Botan::secure_vector<uint8_t> key_rng;
  Botan::secure_vector<uint8_t> key_mac;
  std::vector<uint8_t> server_enc_key;
  std::string username;
};
#endif
