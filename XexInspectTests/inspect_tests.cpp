#include <inspect.h>
#include <pattern_scan.h>

#include <image.h>
#include <xex.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace
{
constexpr uint32_t ImageBase = 0x82000000U;
constexpr uint32_t ImageSize = 0x500U;
constexpr uint32_t EntryPoint = ImageBase + 0x220U;
constexpr uint32_t TitleId = 0x415607daU;
constexpr uint32_t MediaId = 0x5a20a6d4U;
constexpr size_t ExecutionOffset = 0x60;
constexpr size_t FormatOffset = 0x80;
constexpr size_t ImportsOffset = 0x90;
constexpr size_t SecurityOffset = 0x160;
constexpr size_t HeaderSize = 0x300;

struct DosHeader
{
    std::array<uint8_t, 60> prefix{};
    uint32_t peOffset{};
};

struct FileHeader
{
    uint16_t machine{};
    uint16_t sectionCount{};
    std::array<uint8_t, 12> unused{};
    uint16_t optionalSize{};
    uint16_t characteristics{};
};

struct SectionHeader
{
    std::array<char, 8> name{};
    uint32_t virtualSize{};
    uint32_t virtualAddress{};
    std::array<uint8_t, 20> unused{};
    uint32_t characteristics{};
};

static_assert(sizeof(DosHeader) == 64);
static_assert(sizeof(FileHeader) == 20);
static_assert(sizeof(SectionHeader) == 40);
static_assert(sizeof(Xex2ExecutionInfo) == 24);

std::vector<uint8_t> SyntheticXex()
{
    constexpr size_t OptionalCount = 5;
    std::vector<uint8_t> bytes(HeaderSize + ImageSize);

    auto *header = reinterpret_cast<Xex2Header *>(bytes.data());
    header->magic = 0x58455832U;
    header->headerSize = HeaderSize;
    header->securityOffset = SecurityOffset;
    header->headerCount = OptionalCount;
    auto *optional = reinterpret_cast<Xex2OptHeader *>(header + 1);
    optional[0].key = XEX_HEADER_EXECUTION_INFO;
    optional[0].offset = ExecutionOffset;
    optional[1].key = XEX_HEADER_FILE_FORMAT_INFO;
    optional[1].offset = FormatOffset;
    optional[2].key = XEX_HEADER_IMAGE_BASE_ADDRESS;
    optional[2].value = ImageBase;
    optional[3].key = XEX_HEADER_ENTRY_POINT;
    optional[3].value = EntryPoint;
    optional[4].key = XEX_HEADER_IMPORT_LIBRARIES;
    optional[4].offset = ImportsOffset;

    auto *execution = reinterpret_cast<Xex2ExecutionInfo *>(bytes.data() + ExecutionOffset);
    execution->mediaId = MediaId;
    execution->version = 0x00010000U;
    execution->baseVersion = 0x00010000U;
    execution->titleId = TitleId;
    execution->platform = 2;
    execution->discNumber = 1;
    execution->discCount = 1;
    execution->savegameId = TitleId;

    auto *format = reinterpret_cast<Xex2OptFileFormatInfo *>(bytes.data() + FormatOffset);
    format->infoSize = sizeof(Xex2OptFileFormatInfo);
    format->encryptionType = XEX_ENCRYPTION_NONE;
    format->compressionType = XEX_COMPRESSION_NONE;

    auto *importHeader = reinterpret_cast<Xex2ImportHeader *>(bytes.data() + ImportsOffset);
    importHeader->sizeOfHeader =
        sizeof(Xex2ImportHeader) + 8 + sizeof(Xex2ImportLibrary) + 3 * sizeof(Xex2ImportDescriptor);
    importHeader->sizeOfStringTable = 8;
    importHeader->numImports = 1;
    char *importName = reinterpret_cast<char *>(importHeader + 1);
    std::memcpy(importName, "xam.xex", 8);
    auto *library = reinterpret_cast<Xex2ImportLibrary *>(importName + 8);
    library->size = sizeof(Xex2ImportLibrary) + 3 * sizeof(Xex2ImportDescriptor);
    library->name = 0;
    library->numberOfImports = 3;
    auto *descriptors = reinterpret_cast<Xex2ImportDescriptor *>(library + 1);
    descriptors[0].firstThunk = ImageBase + 0x200;
    descriptors[1].firstThunk = ImageBase + 0x220;
    descriptors[2].firstThunk = ImageBase + 0x240;

    auto *security = reinterpret_cast<Xex2SecurityInfo *>(bytes.data() + SecurityOffset);
    security->headerSize = sizeof(Xex2SecurityInfo);
    security->imageSize = ImageSize;
    security->loadAddress = ImageBase;

    uint8_t *image = bytes.data() + HeaderSize;
    auto *dos = reinterpret_cast<DosHeader *>(image);
    dos->peOffset = 0x80;
    uint8_t *nt = image + dos->peOffset;
    *reinterpret_cast<uint32_t *>(nt) = 0x00004550U;
    auto *file = reinterpret_cast<FileHeader *>(nt + sizeof(uint32_t));
    file->sectionCount = 1;
    file->optionalSize = 224;
    *reinterpret_cast<uint32_t *>(nt + 4 + sizeof(FileHeader) + 56) = ImageSize;
    auto *section = reinterpret_cast<SectionHeader *>(nt + 4 + sizeof(FileHeader) + 224);
    std::memcpy(section->name.data(), ".XBMOVIE", section->name.size());
    section->virtualSize = 0x80;
    section->virtualAddress = 0x200;
    section->characteristics = 0x00000020U;
    auto setImport = [image](size_t offset, uint32_t ordinal, uint32_t type)
    {
        auto *thunk = reinterpret_cast<Xex2ThunkData *>(image + offset);
        thunk->data = ByteSwap((type << 24U) | ordinal);
    };
    setImport(0x200, 1, 0);
    setImport(0x220, 1, 1);
    setImport(0x240, 2, 0);
    const std::array<uint8_t, 4> helperPattern{0xe9, 0xc1, 0xff, 0x68};
    std::copy(helperPattern.begin(), helperPattern.end(), image + 0x260);
    return bytes;
}

bool Check(bool condition, const char *label)
{
    std::cout << (condition ? "ok   " : "FAIL ") << label << '\n';
    return condition;
}

bool CheckRefusal(std::vector<uint8_t> &&bytes, const char *errorFragment, const char *label)
{
    XexInspection inspection;
    inspection.imageBytes.push_back(0xffU);
    std::string error;
    const bool refused = !InspectXex(bytes, inspection, error);
    return Check(refused && error.find(errorFragment) != std::string::npos &&
                     inspection.imageBytes.empty(),
                 label);
}
} // namespace

int main()
{
    bool passed = true;
    std::string error;
    XexInspection inspection;
    const std::vector<uint8_t> xex = SyntheticXex();
    passed &= Check(InspectXex(xex, inspection, error), "synthetic XEX inspection");
    passed &=
        Check(inspection.execution.titleId == TitleId && inspection.execution.mediaId == MediaId,
              "execution metadata has distinct title and media IDs");
    passed &= Check(inspection.imageBase == ImageBase && inspection.imageSize == ImageSize &&
                        inspection.entryPoint == EntryPoint,
                    "decrypted image layout");
    passed &=
        Check(inspection.imageBytes.size() == ImageSize && inspection.imageBytes[0x260] == 0xe9U,
              "exact decrypted image bytes");
    passed &= Check(inspection.sections.size() == 1 && inspection.sections[0].code &&
                        inspection.sections[0].base == ImageBase + 0x200 &&
                        inspection.sections[0].name == ".XBMOVIE",
                    "code-section range and bounded eight-byte name");
    passed &= Check(inspection.imports.size() == 2 && inspection.imports[0].function &&
                        inspection.imports[0].address == ImageBase + 0x220 &&
                        inspection.imports[0].recordAddress == ImageBase + 0x200 &&
                        !inspection.imports[1].function &&
                        inspection.imports[1].address == ImageBase + 0x240 &&
                        inspection.imports[1].recordAddress == ImageBase + 0x240,
                    "paired function record and true variable stay distinct");
    const auto helper =
        std::find_if(inspection.helpers.begin(), inspection.helpers.end(),
                     [](const PatternMatches &value) { return value.name == "restgprlr_14"; });
    passed &= Check(helper != inspection.helpers.end() &&
                        helper->addresses == std::vector<uint32_t>{ImageBase + 0x260},
                    "generic code-pattern helper address");
    const std::string json = RenderInspectionJson(inspection);
    passed &= Check(json.find("\"title_id\": \"415607da\"") != std::string::npos &&
                        json.find("\"media_id\": \"5a20a6d4\"") != std::string::npos &&
                        json.find("\"record_address\": \"82000200\"") != std::string::npos,
                    "machine-readable metadata discriminators");

    std::vector<uint8_t> basic = xex;
    auto *basicFormat = reinterpret_cast<Xex2OptFileFormatInfo *>(basic.data() + FormatOffset);
    basicFormat->infoSize = sizeof(Xex2OptFileFormatInfo) + sizeof(Xex2FileBasicCompressionBlock);
    basicFormat->compressionType = XEX_COMPRESSION_BASIC;
    auto *basicBlock = reinterpret_cast<Xex2FileBasicCompressionBlock *>(basicFormat + 1);
    basicBlock->dataSize = ImageSize;
    basicBlock->zeroSize = 0;
    passed &=
        Check(InspectXex(basic, inspection, error) && inspection.imageBytes.size() == ImageSize,
              "valid basic-compression image");

    std::vector<uint8_t> malformed = xex;
    auto *header = reinterpret_cast<Xex2Header *>(malformed.data());
    header->headerCount = 0xffffffffU;
    passed &= CheckRefusal(std::move(malformed), "optional-header",
                           "malformed optional-header table refusal");

    malformed = xex;
    auto *optional = reinterpret_cast<Xex2OptHeader *>(malformed.data() + sizeof(Xex2Header));
    optional[0].key = XEX_HEADER_RESOURCE_INFO;
    passed &= CheckRefusal(std::move(malformed), "missing", "missing execution metadata refusal");

    malformed = xex;
    header = reinterpret_cast<Xex2Header *>(malformed.data());
    header->securityOffset = HeaderSize - 4;
    passed &= CheckRefusal(std::move(malformed), "security header",
                           "out-of-range security header refusal");

    malformed = xex;
    optional = reinterpret_cast<Xex2OptHeader *>(malformed.data() + sizeof(Xex2Header));
    optional[1].offset = HeaderSize - 4;
    passed &= CheckRefusal(std::move(malformed), "optional header",
                           "out-of-range file-format header refusal");

    malformed = xex;
    auto *security = reinterpret_cast<Xex2SecurityInfo *>(malformed.data() + SecurityOffset);
    security->imageSize = ImageSize + 1;
    passed &= CheckRefusal(std::move(malformed), "exceeds the payload",
                           "uncompressed image-size overread refusal");

    malformed = xex;
    auto *format = reinterpret_cast<Xex2OptFileFormatInfo *>(malformed.data() + FormatOffset);
    format->encryptionType = XEX_ENCRYPTION_NORMAL;
    malformed.pop_back();
    passed &=
        CheckRefusal(std::move(malformed), "AES-block aligned", "partial encrypted block refusal");

    malformed = xex;
    format = reinterpret_cast<Xex2OptFileFormatInfo *>(malformed.data() + FormatOffset);
    format->compressionType = XEX_COMPRESSION_BASIC;
    passed &= CheckRefusal(std::move(malformed), "block table is empty",
                           "empty basic-compression block table refusal");

    malformed = xex;
    auto *dos = reinterpret_cast<DosHeader *>(malformed.data() + HeaderSize);
    dos->peOffset = ImageSize;
    passed &= CheckRefusal(std::move(malformed), "PE signature", "out-of-range PE header refusal");

    malformed = xex;
    auto *section = reinterpret_cast<SectionHeader *>(malformed.data() + HeaderSize + 0x80 + 4 +
                                                      sizeof(FileHeader) + 224);
    section->virtualSize = ImageSize;
    passed &=
        CheckRefusal(std::move(malformed), "section exceeds", "out-of-range PE section refusal");

    malformed = xex;
    auto *importHeader = reinterpret_cast<Xex2ImportHeader *>(malformed.data() + ImportsOffset);
    importHeader->sizeOfHeader = HeaderSize;
    passed &= CheckRefusal(std::move(malformed), "import header exceeds",
                           "out-of-range import header refusal");

    malformed = xex;
    malformed[ImportsOffset + sizeof(Xex2ImportHeader) + 7] = 'z';
    passed &=
        CheckRefusal(std::move(malformed), "not terminated", "unterminated import string refusal");

    malformed = xex;
    auto *library = reinterpret_cast<Xex2ImportLibrary *>(malformed.data() + ImportsOffset +
                                                          sizeof(Xex2ImportHeader) + 8);
    library->size = 0xffffffffU;
    passed &=
        CheckRefusal(std::move(malformed), "library size", "out-of-range import library refusal");

    malformed = xex;
    library = reinterpret_cast<Xex2ImportLibrary *>(malformed.data() + ImportsOffset +
                                                    sizeof(Xex2ImportHeader) + 8);
    auto *descriptors = reinterpret_cast<Xex2ImportDescriptor *>(library + 1);
    descriptors[0].firstThunk = ImageBase + 0x100;
    passed &=
        CheckRefusal(std::move(malformed), "outside a mapped", "unmapped import record refusal");

    malformed = xex;
    section = reinterpret_cast<SectionHeader *>(malformed.data() + HeaderSize + 0x80 + 4 +
                                                sizeof(FileHeader) + 224);
    section->virtualSize = 0x44;
    library = reinterpret_cast<Xex2ImportLibrary *>(malformed.data() + ImportsOffset +
                                                    sizeof(Xex2ImportHeader) + 8);
    descriptors = reinterpret_cast<Xex2ImportDescriptor *>(library + 1);
    descriptors[1].firstThunk = ImageBase + 0x238;
    auto *shortThunk = reinterpret_cast<Xex2ThunkData *>(malformed.data() + HeaderSize + 0x238);
    shortThunk->data = ByteSwap((1U << 24U) | 1U);
    passed &=
        CheckRefusal(std::move(malformed), "16 mapped bytes", "short function-thunk range refusal");

    malformed = xex;
    auto *image = malformed.data() + HeaderSize;
    auto *record = reinterpret_cast<Xex2ThunkData *>(image + 0x240);
    record->data = ByteSwap((2U << 24U) | 2U);
    passed &=
        CheckRefusal(std::move(malformed), "unknown thunk type", "unknown import type refusal");

    malformed = xex;
    image = malformed.data() + HeaderSize;
    record = reinterpret_cast<Xex2ThunkData *>(image + 0x200);
    record->data = ByteSwap((1U << 24U) | 1U);
    passed &=
        CheckRefusal(std::move(malformed), "lacks an adjacent", "orphan function thunk refusal");

    malformed = xex;
    image = malformed.data() + HeaderSize;
    record = reinterpret_cast<Xex2ThunkData *>(image + 0x220);
    record->data = ByteSwap((1U << 24U) | 3U);
    passed &=
        CheckRefusal(std::move(malformed), "disagree", "mismatched adjacent import pair refusal");

    malformed = xex;
    image = malformed.data() + HeaderSize;
    record = reinterpret_cast<Xex2ThunkData *>(image + 0x240);
    record->data = ByteSwap(1U);
    passed &= CheckRefusal(std::move(malformed), "library-and-ordinal",
                           "duplicate logical import identity refusal");

    malformed = xex;
    library = reinterpret_cast<Xex2ImportLibrary *>(malformed.data() + ImportsOffset +
                                                    sizeof(Xex2ImportHeader) + 8);
    descriptors = reinterpret_cast<Xex2ImportDescriptor *>(library + 1);
    descriptors[2].firstThunk = descriptors[0].firstThunk;
    passed &= CheckRefusal(std::move(malformed), "address is duplicated",
                           "duplicate import descriptor refusal");

    Sha256Digest digest{};
    const std::array<uint8_t, 3> abc{'a', 'b', 'c'};
    passed &= Check(ComputeSha256(abc.data(), abc.size(), digest, error) &&
                        Sha256Hex(digest) ==
                            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    "OpenSSL SHA-256 positive vector");
    std::array<uint8_t, 3> abd{'a', 'b', 'd'};
    Sha256Digest different{};
    passed &= Check(ComputeSha256(abd.data(), abd.size(), different, error) && digest != different,
                    "OpenSSL SHA-256 negative discriminator");

    std::cout << "xex-inspect tests: " << (passed ? "PASS" : "FAIL") << '\n';
    return passed ? 0 : 1;
}
