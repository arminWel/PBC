#include "common.h"
#include <botan/data_src.h>
#include <botan/pk_keys.h>
#include <botan/x509_key.h>

namespace PBC {
std::unique_ptr<Botan::Public_Key> load_key(const std::string &key) {
  Botan::DataSource_Memory data(key);
  return Botan::X509::load_key(data);
};
} // namespace PBC
