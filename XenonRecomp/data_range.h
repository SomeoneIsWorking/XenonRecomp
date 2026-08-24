#pragma once

#include <cstddef>
#include <vector>

struct Image;

struct RecompilerDataRange
{
    std::size_t address{};
    std::size_t size{};
};

void ValidateDataRanges(std::vector<RecompilerDataRange> &ranges, const Image &image);
const RecompilerDataRange *DataRangeContaining(const std::vector<RecompilerDataRange> &ranges,
                                               std::size_t address);
std::size_t DataRangeScanSkip(const std::vector<RecompilerDataRange> &ranges, std::size_t address);
std::size_t NextDataRangeStart(const std::vector<RecompilerDataRange> &ranges, std::size_t address,
                               std::size_t fallback);
