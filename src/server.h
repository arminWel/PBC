#ifndef srcserverserver_
#define srcserverserver_

#include <botan/secmem.h>
#include <nlohmann/json.hpp>
#include <string>
using json = nlohmann::json;
class Server {
public:
  Server(Botan::secure_vector<char> db_password);
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
  std::string register_user(const std::string &username,
                            const std::string &user_pub_key_view);

private:
  std::string db_name;
  json db;
  Botan::secure_vector<char> db_password;
  /**
   * @brief Create a json entry using the given parameters and
   * write it to the database  db. Throws an invalid argument, if the
   * user already exists.
   *
   * @param username username, under which the data is safed.
   * Should be unique.
   * @param user_pub_key X509 encoded public key of the user.
   * @param server_dec_key encrypted private key of the
   * server.
   */
  void add_user_entry_to_db(const std::string &username,
                            const std::string &user_pub_key,
                            const std::string &server_dec_key);

  void write_db();
  friend class ServerTest;
};

#endif // srcserverserver_
