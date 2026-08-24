#include "data_range.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

#include <fmt/format.h>
#include <image.h>

namespace
{
bool Overlaps(std::size_t first, std::size_t firstSize, std::size_t second, std::size_t secondSize)
{
    return first < second ? firstSize > second - first : secondSize > first - second;
}
} // namespace

void ValidateDataRanges(std::vector<RecompilerDataRange> &ranges, const Image &image)
{
    std::sort(ranges.begin(), ranges.end(),
              [](const auto &left, const auto &right) { return left.address < right.address; });
    for (std::size_t index = 0; index < ranges.size(); ++index)
    {
        const auto &range = ranges[index];
        if (range.size == 0 || range.address % 4 != 0 || range.size % 4 != 0 ||
            range.address > std::numeric_limits<std::size_t>::max() - range.size)
        {
            throw std::runtime_error(
                fmt::format("invalid data range 0x{:X}+0x{:X}", range.address, range.size));
        }
        if (index != 0 && ranges[index - 1].address + ranges[index - 1].size > range.address)
        {
            throw std::runtime_error(
                fmt::format("overlapping data range at 0x{:X}", range.address));
        }

        const auto section = std::find_if(
            image.sections.begin(), image.sections.end(),
            [&](const auto &candidate)
            {
                if (!(candidate.flags & SectionFlags_Code) || range.address < candidate.base)
                {
                    return false;
                }
                const auto offset = range.address - candidate.base;
                return offset <= candidate.size && range.size <= candidate.size - offset;
            });
        if (section == image.sections.end())
        {
            throw std::runtime_error(
                fmt::format("data range 0x{:X}+0x{:X} is not inside one code section",
                            range.address, range.size));
        }
        const auto symbol = std::find_if(image.symbols.begin(), image.symbols.end(),
                                         [&](const auto &candidate)
                                         {
                                             return candidate.type == Symbol_Function &&
                                                    Overlaps(range.address, range.size,
                                                             candidate.address, candidate.size);
                                         });
        if (symbol != image.symbols.end())
        {
            throw std::runtime_error(fmt::format("data range 0x{:X}+0x{:X} overlaps function {}",
                                                 range.address, range.size, symbol->name));
        }
    }
}

const RecompilerDataRange *DataRangeContaining(const std::vector<RecompilerDataRange> &ranges,
                                               std::size_t address)
{
    const auto next = std::upper_bound(ranges.begin(), ranges.end(), address,
                                       [](std::size_t value, const auto &range)
                                       { return value < range.address; });
    if (next == ranges.begin())
    {
        return nullptr;
    }
    const auto &range = *std::prev(next);
    return address < range.address + range.size ? &range : nullptr;
}

std::size_t DataRangeScanSkip(const std::vector<RecompilerDataRange> &ranges, std::size_t address)
{
    const auto *range = DataRangeContaining(ranges, address);
    if (range == nullptr)
    {
        return 0;
    }
    if (address != range->address)
    {
        throw std::runtime_error(fmt::format("function scan entered data range 0x{:X}+0x{:X}",
                                             range->address, range->size));
    }
    return range->size;
}

std::size_t NextDataRangeStart(const std::vector<RecompilerDataRange> &ranges, std::size_t address,
                               std::size_t fallback)
{
    const auto next = std::upper_bound(ranges.begin(), ranges.end(), address,
                                       [](std::size_t value, const auto &range)
                                       { return value < range.address; });
    return next != ranges.end() && next->address < fallback ? next->address : fallback;
}
