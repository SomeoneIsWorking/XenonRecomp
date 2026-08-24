#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <image.h>

#include "data_range.h"
#include "recompiler_config.h"

namespace
{
void Require(bool condition, const char *message)
{
    if (!condition)
    {
        std::cerr << "data range test failed: " << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}

template <typename Action> void RequireRefusal(Action action, const char *message)
{
    try
    {
        action();
    }
    catch (const std::runtime_error &)
    {
        return;
    }
    Require(false, message);
}

Image CodeImage()
{
    Image image;
    image.sections.emplace(Section{"text", 0x1000, 0x100, SectionFlags_Code, nullptr});
    image.sections.emplace(Section{"data", 0x2000, 0x100, SectionFlags_Data, nullptr});
    return image;
}

void WriteConfig(const char *path, const std::string &dataRanges)
{
    std::ofstream output(path, std::ios::trunc);
    Require(output.good(), "could not create parser fixture");
    output << "[main]\n" << dataRanges << '\n';
    Require(output.good(), "could not write parser fixture");
}
} // namespace

int main()
{
    auto image = CodeImage();
    std::vector<RecompilerDataRange> ranges{{0x1020, 8}, {0x1008, 8}};
    ValidateDataRanges(ranges, image);
    Require(ranges[0].address == 0x1008, "ranges were not normalized by address");
    Require(DataRangeContaining(ranges, 0x1008) == &ranges[0], "exact range start not found");
    Require(DataRangeContaining(ranges, 0x100C) == &ranges[0], "range interior not found");
    Require(DataRangeContaining(ranges, 0x1010) == nullptr, "range end treated as data");
    Require(DataRangeScanSkip(ranges, 0x1008) == 8, "scan did not skip an exact range start");
    Require(DataRangeScanSkip(ranges, 0x1010) == 0, "scan skipped ordinary code");
    RequireRefusal([&] { DataRangeScanSkip(ranges, 0x100C); },
                   "scan accepted a data-range interior address");
    Require(NextDataRangeStart(ranges, 0x1000, 0x1100) == 0x1008,
            "next range did not bound the gap");

    RequireRefusal(
        [&]
        {
            std::vector<RecompilerDataRange> invalid{{0x1008, 0}};
            ValidateDataRanges(invalid, image);
        },
        "zero-sized range was accepted");
    RequireRefusal(
        [&]
        {
            std::vector<RecompilerDataRange> invalid{{0x1008, 8}, {0x100C, 8}};
            ValidateDataRanges(invalid, image);
        },
        "overlapping ranges were accepted");
    RequireRefusal(
        [&]
        {
            std::vector<RecompilerDataRange> invalid{{0x2000, 8}};
            ValidateDataRanges(invalid, image);
        },
        "range in a data section was accepted");

    auto functionImage = CodeImage();
    functionImage.symbols.emplace("owner", 0x1008, 0x20, Symbol_Function);
    RequireRefusal(
        [&]
        {
            std::vector<RecompilerDataRange> invalid{{0x1008, 8}};
            ValidateDataRanges(invalid, functionImage);
        },
        "range overlapping an authoritative function was accepted");

    constexpr auto configPath = "data_range_config_test.toml";
    WriteConfig(configPath, "data_ranges = [{ address = 0x1008, size = 8 }]");
    RecompilerConfig config;
    config.Load(configPath);
    Require(config.dataRanges.size() == 1 && config.dataRanges[0].address == 0x1008 &&
                config.dataRanges[0].size == 8,
            "valid config range was not parsed");

    RequireRefusal(
        [&]
        {
            WriteConfig(configPath, "data_ranges = [{ address = 0x1008 }]");
            RecompilerConfig invalid;
            invalid.Load(configPath);
        },
        "config range missing size was accepted");
    RequireRefusal(
        [&]
        {
            WriteConfig(configPath, "data_ranges = [{ address = \"0x1008\", size = 8 }]");
            RecompilerConfig invalid;
            invalid.Load(configPath);
        },
        "config range with wrong address type was accepted");
    RequireRefusal(
        [&]
        {
            WriteConfig(configPath, "data_ranges = { address = 0x1008, size = 8 }");
            RecompilerConfig invalid;
            invalid.Load(configPath);
        },
        "config data_ranges table was accepted instead of an array");

    std::cout << "data range test passed: runtime and parser contradictions refused\n";
    return EXIT_SUCCESS;
}
