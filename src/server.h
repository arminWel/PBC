#ifndef srcserverserver_
#define srcserverserver_

#include "Cellar/nlohmann-json/3.11.3/include/nlohmann/json_fwd.hpp"
#include <botan/secmem.h>
#include <nlohmann/json.hpp>
#include <string>
using json = nlohmann::json;
class Server {
public:
  /**
   * @brief Registers a user. Generate a RSA encryption key
   * pair, where the private key is saved alongside with the
   * username and user public key to the database.
   *
   * @param username name of the user to be registered, must
   * be unique.
   * @param user_pub_key_view X509 encoded public signing key
   * of the user.
   * @return X509 encoded public encryption key of the server.
   */
  std::vector<uint8_t> register_user(std::string &username,
                                     std::vector<uint8_t> &user_pub_key_view);

private:
  std::string db_name;
  json db;
  Botan::secure_vector<char> db_password;
  /**
   * @brief Create a json entry using the given parameters and
   * write it to the database  db.
   *
   * @param username username, under which the data is safed.
   * Should be unique.
   * @param user_pub_key X509 encoded public key of the user.
   * @param server_dec_key encrypted private key of the
   * server.
   */
  void add_user_entry_to_db(std::string &username,
                            std::vector<uint8_t> &user_pub_key,
                            std::vector<uint8_t> &server_dec_key);
  void write_db();
};

#endif // srcserverserver_
