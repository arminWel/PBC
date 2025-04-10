#ifndef PBCIMPCOMMON
#define PBCIMPCOMMON

#include <botan/data_src.h>
#include <botan/pk_keys.h>
#include <botan/x509_key.h>
#include <memory>
namespace PBC {
std::unique_ptr<Botan::Public_Key> load_key(const std::string &key);
}

#endif // PBCIMPCOMMON
