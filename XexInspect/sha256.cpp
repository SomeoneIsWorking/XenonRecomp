#include "sha256.h"

#include <openssl/evp.h>

#include <iomanip>
#include <memory>
#include <sstream>

namespace
{
struct DigestContextDeleter
{
    void operator()(EVP_MD_CTX *context) const { EVP_MD_CTX_free(context); }
};
} // namespace

bool ComputeSha256(const uint8_t *data, size_t size, Sha256Digest &digest, std::string &error)
{
    digest = {};
    if (data == nullptr && size != 0)
    {
        error = "SHA-256 input pointer is null";
        return false;
    }

    std::unique_ptr<EVP_MD_CTX, DigestContextDeleter> context(EVP_MD_CTX_new());
    if (context == nullptr || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(context.get(), data, size) != 1)
    {
        error = "OpenSSL could not initialize SHA-256";
        return false;
    }

    unsigned int digestSize = 0;
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &digestSize) != 1 ||
        digestSize != digest.size())
    {
        error = "OpenSSL returned an invalid SHA-256 digest";
        digest = {};
        return false;
    }
    error.clear();
    return true;
}

std::string Sha256Hex(const Sha256Digest &digest)
{
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (const uint8_t byte : digest)
    {
        stream << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return stream.str();
}
