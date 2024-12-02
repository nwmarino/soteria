#ifndef SOTERIA_ENCRYPTION_AES_H
#define SOTERIA_ENCRYPTION_AES_H

#include <string>
#include <vector>

namespace soteria {

/// \returns A random byte array.
/// \param len The length of the byte array.
std::vector<unsigned char> generate_rand(const std::size_t len = 32);

/// \returns The SHA-256 hash of \p data.
/// \param data The data to hash.
const std::string generate_sha256(const std::vector<unsigned char> &data);

/// \returns AES-256-CBC encrypted data.
/// \param data The data to encrypt.
/// \param key The encryption key.
/// \param iv The initialization vector.
std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char> &data,
                                       const std::vector<unsigned char> &key,
                                       const std::vector<unsigned char> &iv);

/// \returns AES-256-CBC decrypted data.
/// \param data The data to decrypt.
/// \param key The decryption key.
/// \param iv The initialization vector.
std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char> &data,
                                       const std::vector<unsigned char> &key,
                                       const std::vector<unsigned char> &iv);

/// \returns A hashed password.
/// \param data The password to hash.
/// \param salt The salt to use.
/// \param iterations The number of iterations to hash.
/// \param len The length of the hash.
std::vector<unsigned char> hash_password(const std::string &data,
                                         const std::vector<unsigned char> &salt,
                                         const unsigned int iterations = 100000,
                                         const unsigned int len = 32);

/// \returns Matches the stored password with the input password.
/// \param stored The stored password hash.
/// \param password The input password.
/// \param salt The salt used to hash the password.
bool match_password(const std::string &stored, const std::string &password,
                    const std::vector<unsigned char> &salt);

} // end namespace soteria

#endif // SOTERIA_ENCRYPTION_AES_H
