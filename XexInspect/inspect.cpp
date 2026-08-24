#include "inspect.h"
#include "pattern_scan.h"

#include <image.h>

#include <iomanip>
#include <limits>
#include <sstream>
#include <utility>

namespace
{
struct HelperPattern
{
    const char *name;
    const uint8_t *bytes;
    size_t size;
};

constexpr uint8_t RestGprLr14[] = {0xe9, 0xc1, 0xff, 0x68};
constexpr uint8_t SaveGprLr14[] = {0xf9, 0xc1, 0xff, 0x68};
constexpr uint8_t RestFpr14[] = {0xc9, 0xcc, 0xff, 0x70};
constexpr uint8_t SaveFpr14[] = {0xd9, 0xcc, 0xff, 0x70};
constexpr uint8_t RestVmx14[] = {0x39, 0x60, 0xfe, 0xe0, 0x7d, 0xcb, 0x60, 0xce};
constexpr uint8_t SaveVmx14[] = {0x39, 0x60, 0xfe, 0xe0, 0x7d, 0xcb, 0x61, 0xce};
constexpr uint8_t RestVmx64[] = {0x39, 0x60, 0xfc, 0x00, 0x10, 0x0b, 0x60, 0xcb};
constexpr uint8_t SaveVmx64[] = {0x39, 0x60, 0xfc, 0x00, 0x10, 0x0b, 0x61, 0xcb};

constexpr HelperPattern HelperPatterns[] = {
    {"restgprlr_14", RestGprLr14, sizeof(RestGprLr14)},
    {"savegprlr_14", SaveGprLr14, sizeof(SaveGprLr14)},
    {"restfpr_14", RestFpr14, sizeof(RestFpr14)},
    {"savefpr_14", SaveFpr14, sizeof(SaveFpr14)},
    {"restvmx_14", RestVmx14, sizeof(RestVmx14)},
    {"savevmx_14", SaveVmx14, sizeof(SaveVmx14)},
    {"restvmx_64", RestVmx64, sizeof(RestVmx64)},
    {"savevmx_64", SaveVmx64, sizeof(SaveVmx64)},
};

std::string Hex32(uint32_t value)
{
    std::ostringstream stream;
    stream << std::hex << std::setfill('0') << std::setw(8) << value;
    return stream.str();
}

std::string JsonString(const std::string &value)
{
    std::ostringstream stream;
    stream << '"';
    for (const unsigned char character : value)
    {
        switch (character)
        {
        case '"':
            stream << "\\\"";
            break;
        case '\\':
            stream << "\\\\";
            break;
        case '\b':
            stream << "\\b";
            break;
        case '\f':
            stream << "\\f";
            break;
        case '\n':
            stream << "\\n";
            break;
        case '\r':
            stream << "\\r";
            break;
        case '\t':
            stream << "\\t";
            break;
        default:
            if (character < 0x20U)
            {
                stream << "\\u" << std::hex << std::setfill('0') << std::setw(4)
                       << static_cast<unsigned int>(character) << std::dec;
            }
            else
            {
                stream << static_cast<char>(character);
            }
            break;
        }
    }
    stream << '"';
    return stream.str();
}
} // namespace

bool InspectXex(const std::vector<uint8_t> &xex, XexInspection &inspection, std::string &error)
{
    inspection = {};
    XexInspection candidate;
    if (!ComputeSha256(xex.data(), xex.size(), candidate.xexSha256, error))
    {
        return false;
    }

    Image image;
    if (!TryLoadXex(xex.data(), xex.size(), image, candidate.execution, error))
    {
        return false;
    }
    if (image.base > std::numeric_limits<uint32_t>::max() ||
        image.entry_point > std::numeric_limits<uint32_t>::max())
    {
        error = "XEX2 image layout exceeds the 32-bit guest address space";
        return false;
    }

    candidate.xexSize = xex.size();
    candidate.imageBase = static_cast<uint32_t>(image.base);
    candidate.imageSize = image.size;
    candidate.entryPoint = static_cast<uint32_t>(image.entry_point);
    for (const Section &section : image.sections)
    {
        if (section.base > std::numeric_limits<uint32_t>::max())
        {
            error = "XEX2 section address exceeds the 32-bit guest address space";
            return false;
        }
        candidate.sections.push_back({section.name, static_cast<uint32_t>(section.base),
                                      section.size, (section.flags & SectionFlags_Code) != 0});
    }
    for (const ImportSymbol &import : image.imports)
    {
        candidate.imports.push_back({import.name, import.library, import.thunkAddress,
                                     import.recordAddress, import.ordinal,
                                     import.kind == ImportKind::Function});
    }
    for (const HelperPattern &helper : HelperPatterns)
    {
        candidate.helpers.push_back(
            {helper.name, FindCodePattern(image, helper.bytes, helper.size)});
    }
    candidate.imageBytes.assign(image.data.get(), image.data.get() + image.size);
    if (!ComputeSha256(candidate.imageBytes.data(), candidate.imageBytes.size(),
                       candidate.imageSha256, error))
    {
        return false;
    }
    inspection = std::move(candidate);
    error.clear();
    return true;
}

std::string RenderInspectionJson(const XexInspection &inspection)
{
    std::ostringstream stream;
    stream << "{\n"
           << "  \"schema\": 1,\n"
           << "  \"format\": \"XEX2\",\n"
           << "  \"xex\": {\n"
           << "    \"sha256\": \"" << Sha256Hex(inspection.xexSha256) << "\",\n"
           << "    \"size\": " << inspection.xexSize << "\n"
           << "  },\n"
           << "  \"execution\": {\n"
           << "    \"title_id\": \"" << Hex32(inspection.execution.titleId) << "\",\n"
           << "    \"media_id\": \"" << Hex32(inspection.execution.mediaId) << "\",\n"
           << "    \"version\": \"" << Hex32(inspection.execution.version) << "\",\n"
           << "    \"base_version\": \"" << Hex32(inspection.execution.baseVersion) << "\",\n"
           << "    \"platform\": " << static_cast<unsigned int>(inspection.execution.platform)
           << ",\n"
           << "    \"executable_table\": "
           << static_cast<unsigned int>(inspection.execution.executableTable) << ",\n"
           << "    \"disc_number\": " << static_cast<unsigned int>(inspection.execution.discNumber)
           << ",\n"
           << "    \"disc_count\": " << static_cast<unsigned int>(inspection.execution.discCount)
           << ",\n"
           << "    \"savegame_id\": \"" << Hex32(inspection.execution.savegameId) << "\"\n"
           << "  },\n"
           << "  \"image\": {\n"
           << "    \"sha256\": \"" << Sha256Hex(inspection.imageSha256) << "\",\n"
           << "    \"base\": \"" << Hex32(inspection.imageBase) << "\",\n"
           << "    \"size\": " << inspection.imageSize << ",\n"
           << "    \"entry\": \"" << Hex32(inspection.entryPoint) << "\"\n"
           << "  },\n"
           << "  \"sections\": [\n";
    for (size_t index = 0; index < inspection.sections.size(); ++index)
    {
        const InspectedSection &section = inspection.sections[index];
        stream << "    {\"name\": " << JsonString(section.name) << ", \"base\": \""
               << Hex32(section.base) << "\", \"size\": " << section.size
               << ", \"code\": " << (section.code ? "true" : "false") << "}"
               << (index + 1 == inspection.sections.size() ? "\n" : ",\n");
    }
    stream << "  ],\n"
           << "  \"imports\": [\n";
    for (size_t index = 0; index < inspection.imports.size(); ++index)
    {
        const InspectedImport &import = inspection.imports[index];
        stream << "    {\"kind\": \"" << (import.function ? "function" : "variable")
               << "\", \"library\": " << JsonString(import.library)
               << ", \"ordinal\": " << import.ordinal << ", \"name\": " << JsonString(import.name)
               << ", \"address\": \"" << Hex32(import.address) << "\", \"record_address\": \""
               << Hex32(import.recordAddress) << "\"}"
               << (index + 1 == inspection.imports.size() ? "\n" : ",\n");
    }
    stream << "  ],\n"
           << "  \"helpers\": {\n";
    for (size_t helperIndex = 0; helperIndex < inspection.helpers.size(); ++helperIndex)
    {
        const PatternMatches &helper = inspection.helpers[helperIndex];
        stream << "    " << JsonString(helper.name) << ": [";
        for (size_t addressIndex = 0; addressIndex < helper.addresses.size(); ++addressIndex)
        {
            stream << '"' << Hex32(helper.addresses[addressIndex]) << '"';
            if (addressIndex + 1 != helper.addresses.size())
            {
                stream << ", ";
            }
        }
        stream << ']' << (helperIndex + 1 == inspection.helpers.size() ? "\n" : ",\n");
    }
    stream << "  }\n"
           << "}\n";
    return stream.str();
}
