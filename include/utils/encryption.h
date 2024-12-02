#ifndef SOTERIA_ENCRYPTION_AES_H
#define SOTERIA_ENCRYPTION_AES_H

#include <string>
#include <vector>

namespace soteria {

void generate_key_iv(std::vector<unsigned char> &key, 
                     std::vector<unsigned char> &iv,
                     std::size_t key_len = 32,
                     std::size_t iv_len = 16);

/// \returns The SHA-256 hash of \p data.
/// \param data The data to hash.
const std::string generate_sha256(const std::vector<unsigned char> &data);

void aes_encrypt_file(const std::string &in_path, const std::string &out_path,
                      const std::vector<unsigned char> &key,
                      const std::vector<unsigned char> &iv);

void aes_decrypt_file(const std::string &in_path, const std::string &out_path,
                      const std::vector<unsigned char> &key);

} // end namespace soteria

#endif // SOTERIA_ENCRYPTION_AES_H
