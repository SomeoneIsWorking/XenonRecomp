#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

using Sha256Digest = std::array<uint8_t, 32>;

bool ComputeSha256(const uint8_t *data, size_t size, Sha256Digest &digest, std::string &error);
std::string Sha256Hex(const Sha256Digest &digest);
