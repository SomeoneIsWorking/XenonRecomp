#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

struct Image;

std::vector<uint32_t> FindCodePattern(const Image &image, const uint8_t *pattern,
                                      size_t patternSize, size_t alignment = 4);
