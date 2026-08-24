#pragma once

#include "sha256.h"

#include <cstdint>
#include <string>
#include <vector>

#include <xex.h>

struct InspectedSection
{
    std::string name{};
    uint32_t base{};
    uint32_t size{};
    bool code{};
};

struct InspectedImport
{
    std::string name{};
    std::string library{};
    uint32_t address{};
    uint32_t recordAddress{};
    uint32_t ordinal{};
    bool function{};
};

struct PatternMatches
{
    std::string name{};
    std::vector<uint32_t> addresses{};
};

struct XexInspection
{
    Sha256Digest xexSha256{};
    uint64_t xexSize{};
    Xex2ExecutionMetadata execution{};
    Sha256Digest imageSha256{};
    uint32_t imageBase{};
    uint32_t imageSize{};
    uint32_t entryPoint{};
    std::vector<InspectedSection> sections{};
    std::vector<InspectedImport> imports{};
    std::vector<PatternMatches> helpers{};
    std::vector<uint8_t> imageBytes{};
};

bool InspectXex(const std::vector<uint8_t> &xex, XexInspection &inspection, std::string &error);
std::string RenderInspectionJson(const XexInspection &inspection);
