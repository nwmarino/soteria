//>==- encryption.h -------------------------------------------------------==<//
//
// This header file declares functions used to encrypt and hash data.
//
//>==----------------------------------------------------------------------==<//

#ifndef SOTERIA_ENCRYPTION_AES_H
#define SOTERIA_ENCRYPTION_AES_H

#include <array>
#include <string>
#include <vector>

namespace soteria {

/// \returns A random byte vector of length \p len.
std::vector<unsigned char> generate_rand(const std::size_t len = 32);

/// \returns A random initialization vector of 16 bytes.
std::array<unsigned char, 16> generate_iv();

/// \returns A random key of 32 bytes.
std::array<unsigned char, 32> generate_key();

/// \returns The SHA-256 checksum of the file at \p path.
std::array<unsigned char, 32> compute_checksum(const std::string &path);

/// \returns The SHA-256 checksum of \p data.
std::array<unsigned char, 32> compute_checksum(const std::vector<unsigned char> &data);

/// \returns AES-256-CBC encrypted data.
/// \param data The data to encrypt.
/// \param key The encryption key.
/// \param iv The initialization vector.
std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char> &data,
                                       const std::array<unsigned char, 32> &key,
                                       const std::array<unsigned char, 16> &iv);

/// \returns AES-256-CBC decrypted data.
/// \param data The data to decrypt.
/// \param key The decryption key.
/// \param iv The initialization vector.
std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char> &data,
                                       const std::array<unsigned char, 32> &key,
                                       const std::array<unsigned char, 16> &iv);

/// \param data The password to hash.
/// \param salt The salt to use.
/// \param iterations The number of iterations to hash.
/// \param len The length of the hash.
std::vector<unsigned char> hash_password(const std::string &data,
                                         const std::vector<unsigned char> &salt,
                                         const unsigned int iterations = 100000,
                                         const unsigned int len = 32);

/// \returns If a hashed \p password matches \p hash.
/// \param stored The stored password hash.
/// \param password The input password.
/// \param salt The salt used to hash the password.
bool match_password(const std::string &password,
                    const std::vector<unsigned char> &hash,
                    const std::vector<unsigned char> &salt);

} // end namespace soteria

#endif // SOTERIA_ENCRYPTION_AES_H
