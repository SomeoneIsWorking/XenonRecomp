#include "pattern_scan.h"

#include <image.h>

#include <cstring>
#include <limits>

std::vector<uint32_t> FindCodePattern(const Image &image, const uint8_t *pattern,
                                      size_t patternSize, size_t alignment)
{
    std::vector<uint32_t> matches;
    if (pattern == nullptr || patternSize == 0 || alignment == 0)
    {
        return matches;
    }
    for (const Section &section : image.sections)
    {
        if ((section.flags & SectionFlags_Code) == 0 || patternSize > section.size)
        {
            continue;
        }
        for (size_t offset = 0; offset <= section.size - patternSize; offset += alignment)
        {
            const size_t address = section.base + offset;
            if (address <= std::numeric_limits<uint32_t>::max() &&
                std::memcmp(section.data + offset, pattern, patternSize) == 0)
            {
                matches.push_back(static_cast<uint32_t>(address));
            }
        }
    }
    return matches;
}
