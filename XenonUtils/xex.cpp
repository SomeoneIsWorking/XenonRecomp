#include "xex.h"
#include "image.h"

#include <aes.hpp>
#include <TinySHA1.hpp>
#include <xex_patcher.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <set>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#define STRINGIFY(X) #X
#define XE_EXPORT(MODULE, ORDINAL, NAME, TYPE) {(ORDINAL), "__imp__" STRINGIFY(NAME)}

std::unordered_map<size_t, const char *> XamExports = {
#include "xbox/xam_table.inc"
};

std::unordered_map<size_t, const char *> XboxKernelExports = {
#include "xbox/xboxkrnl_table.inc"
};

namespace
{
constexpr uint32_t Xex2Magic = 0x58455832U;
constexpr size_t PeSignatureSize = 4;
constexpr size_t PeFileHeaderSize = 20;
constexpr size_t PeSectionHeaderSize = 40;
constexpr size_t PeOffsetField = 0x3c;
constexpr uint32_t PeSignature = 0x00004550U;
constexpr uint32_t PeSectionContainsCode = 0x00000020U;
constexpr size_t ImportLibraryHeaderSize = sizeof(Xex2ImportLibrary);
constexpr size_t ImportFunctionStubSize = 16;

class ByteView
{
  public:
    ByteView(const uint8_t *data, size_t size) : data_(data), size_(size) {}

    size_t Size() const { return size_; }

    bool Contains(size_t offset, size_t length) const
    {
        return offset <= size_ && length <= size_ - offset;
    }

    const uint8_t *Data(size_t offset) const { return data_ + offset; }

    bool ReadU8(size_t offset, uint8_t &value) const { return Copy(offset, value); }

    bool ReadBe16(size_t offset, uint16_t &value) const
    {
        uint16_t encoded{};
        if (!Copy(offset, encoded))
        {
            return false;
        }
        value = ByteSwap(encoded);
        return true;
    }

    bool ReadBe32(size_t offset, uint32_t &value) const
    {
        uint32_t encoded{};
        if (!Copy(offset, encoded))
        {
            return false;
        }
        value = ByteSwap(encoded);
        return true;
    }

    bool ReadLe16(size_t offset, uint16_t &value) const { return Copy(offset, value); }

    bool ReadLe32(size_t offset, uint32_t &value) const { return Copy(offset, value); }

  private:
    template <typename T> bool Copy(size_t offset, T &value) const
    {
        if (!Contains(offset, sizeof(value)))
        {
            return false;
        }
        std::memcpy(&value, data_ + offset, sizeof(value));
        return true;
    }

    const uint8_t *data_{};
    size_t size_{};
};

struct OptionalHeaderValue
{
    uint32_t value{};
};

struct SectionSpec
{
    std::string name{};
    uint32_t virtualAddress{};
    uint32_t virtualSize{};
    uint8_t flags{};
};

struct RawImport
{
    uint32_t address{};
    uint32_t hostValue{};
    uint32_t ordinal{};
    uint8_t type{};
};

bool Refuse(std::string &error, std::string message)
{
    error = std::move(message);
    return false;
}

bool ReadImageBe32(const Image &image, uint32_t address, uint32_t &value)
{
    const void *bytes = image.FindRange(address, sizeof(uint32_t));
    if (bytes == nullptr)
    {
        return false;
    }
    uint32_t encoded{};
    std::memcpy(&encoded, bytes, sizeof(encoded));
    value = ByteSwap(encoded);
    return true;
}

const std::unordered_map<size_t, const char *> *FindExportNames(std::string_view library)
{
    if (library == "xam.xex")
    {
        return &XamExports;
    }
    if (library == "xboxkrnl.exe")
    {
        return &XboxKernelExports;
    }
    return nullptr;
}

std::string ExportName(const std::unordered_map<size_t, const char *> *names, uint32_t ordinal)
{
    if (names == nullptr)
    {
        return {};
    }
    const auto name = names->find(ordinal);
    return name == names->end() ? std::string{} : name->second;
}

bool DecompressImage(const ByteView &xex, size_t headerSize, size_t formatOffset, size_t formatSize,
                     uint16_t encryptionType, uint16_t compressionType,
                     const Xex2SecurityInfo &securityInfo, std::unique_ptr<uint8_t[]> &result,
                     std::string &error)
{
    const uint32_t declaredImageSize = securityInfo.imageSize;
    if (declaredImageSize == 0)
    {
        return Refuse(error, "XEX2 security header declares an empty image");
    }
    if (!xex.Contains(headerSize, 0))
    {
        return Refuse(error, "XEX2 payload offset is outside the input");
    }

    const size_t sourceSize = xex.Size() - headerSize;
    const uint8_t *source = xex.Data(headerSize);
    std::vector<uint8_t> decrypted;

    if (encryptionType == XEX_ENCRYPTION_NORMAL)
    {
        constexpr size_t AesBlockSize = 16;
        if (sourceSize == 0 || sourceSize % AesBlockSize != 0)
        {
            return Refuse(error, "XEX2 encrypted payload is not AES-block aligned");
        }
        decrypted.assign(source, source + sourceSize);

        AES_ctx aesContext;
        std::array<uint8_t, AesBlockSize> decryptedKey{};
        std::memcpy(decryptedKey.data(), securityInfo.aesKey, decryptedKey.size());
        AES_init_ctx_iv(&aesContext, Xex2RetailKey, AESBlankIV);
        AES_CBC_decrypt_buffer(&aesContext, decryptedKey.data(), decryptedKey.size());
        AES_init_ctx_iv(&aesContext, decryptedKey.data(), AESBlankIV);
        AES_CBC_decrypt_buffer(&aesContext, decrypted.data(), decrypted.size());
        source = decrypted.data();
    }
    else if (encryptionType != XEX_ENCRYPTION_NONE)
    {
        return Refuse(error, "XEX2 file-format header has an unsupported encryption type");
    }

    const ByteView sourceView(source, sourceSize);
    if (compressionType == XEX_COMPRESSION_NONE)
    {
        if (!sourceView.Contains(0, declaredImageSize))
        {
            return Refuse(error, "XEX2 uncompressed image exceeds the payload");
        }
        result = std::make_unique<uint8_t[]>(declaredImageSize);
        std::memcpy(result.get(), source, declaredImageSize);
        return true;
    }

    if (compressionType == XEX_COMPRESSION_BASIC)
    {
        if (formatSize < sizeof(Xex2OptFileFormatInfo) ||
            (formatSize - sizeof(Xex2OptFileFormatInfo)) % sizeof(Xex2FileBasicCompressionBlock) !=
                0)
        {
            return Refuse(error, "XEX2 basic-compression block table has an invalid size");
        }

        const size_t blockCount =
            (formatSize - sizeof(Xex2OptFileFormatInfo)) / sizeof(Xex2FileBasicCompressionBlock);
        if (blockCount == 0)
        {
            return Refuse(error, "XEX2 basic-compression block table is empty");
        }

        struct BasicBlock
        {
            uint32_t dataSize;
            uint32_t zeroSize;
        };
        std::vector<BasicBlock> blocks;
        blocks.reserve(blockCount);
        size_t sourceOffset = 0;
        size_t outputOffset = 0;
        for (size_t index = 0; index < blockCount; ++index)
        {
            const size_t blockOffset = formatOffset + sizeof(Xex2OptFileFormatInfo) +
                                       index * sizeof(Xex2FileBasicCompressionBlock);
            uint32_t dataSize{};
            uint32_t zeroSize{};
            if (!xex.ReadBe32(blockOffset, dataSize) ||
                !xex.ReadBe32(blockOffset + sizeof(uint32_t), zeroSize))
            {
                return Refuse(error, "XEX2 basic-compression block table is truncated");
            }
            if (!sourceView.Contains(sourceOffset, dataSize))
            {
                return Refuse(error, "XEX2 basic-compression block exceeds the payload");
            }
            if (outputOffset > declaredImageSize || dataSize > declaredImageSize - outputOffset)
            {
                return Refuse(error, "XEX2 basic-compression data exceeds the declared image");
            }
            outputOffset += dataSize;
            if (zeroSize > declaredImageSize - outputOffset)
            {
                return Refuse(error, "XEX2 basic-compression zero run exceeds the declared image");
            }
            outputOffset += zeroSize;
            sourceOffset += dataSize;
            blocks.push_back({dataSize, zeroSize});
        }
        if (outputOffset != declaredImageSize)
        {
            return Refuse(error,
                          "XEX2 basic-compression blocks do not produce the declared image size");
        }

        result = std::make_unique<uint8_t[]>(declaredImageSize);
        sourceOffset = 0;
        outputOffset = 0;
        for (const BasicBlock &block : blocks)
        {
            std::memcpy(result.get() + outputOffset, source + sourceOffset, block.dataSize);
            outputOffset += block.dataSize;
            sourceOffset += block.dataSize;
            std::memset(result.get() + outputOffset, 0, block.zeroSize);
            outputOffset += block.zeroSize;
        }
        return true;
    }

    if (compressionType != XEX_COMPRESSION_NORMAL)
    {
        return Refuse(error, "XEX2 file-format header has an unsupported compression type");
    }

    constexpr size_t NormalInfoSize =
        sizeof(Xex2OptFileFormatInfo) + sizeof(uint32_t) + sizeof(Xex2CompressedBlockInfo);
    if (formatSize < NormalInfoSize)
    {
        return Refuse(error, "XEX2 normal-compression header is truncated");
    }

    uint32_t windowSize{};
    uint32_t blockSize{};
    if (!xex.ReadBe32(formatOffset + sizeof(Xex2OptFileFormatInfo), windowSize) ||
        !xex.ReadBe32(formatOffset + sizeof(Xex2OptFileFormatInfo) + sizeof(uint32_t), blockSize))
    {
        return Refuse(error, "XEX2 normal-compression header is truncated");
    }
    std::array<uint8_t, 20> blockHash{};
    const size_t firstHashOffset =
        formatOffset + sizeof(Xex2OptFileFormatInfo) + 2 * sizeof(uint32_t);
    if (!xex.Contains(firstHashOffset, blockHash.size()))
    {
        return Refuse(error, "XEX2 normal-compression block hash is truncated");
    }
    std::memcpy(blockHash.data(), xex.Data(firstHashOffset), blockHash.size());

    size_t sourceOffset = 0;
    std::vector<uint8_t> compressed;
    compressed.reserve(sourceSize);
    sha1::SHA1 sha;
    while (blockSize != 0)
    {
        if (blockSize < sizeof(Xex2CompressedBlockInfo) ||
            !sourceView.Contains(sourceOffset, blockSize))
        {
            return Refuse(error, "XEX2 normal-compression block exceeds the payload");
        }

        std::array<uint8_t, 20> calculatedHash{};
        sha.reset();
        sha.processBytes(source + sourceOffset, blockSize);
        sha.finalize(calculatedHash.data());
        if (calculatedHash != blockHash)
        {
            return Refuse(error, "XEX2 normal-compression block hash does not match");
        }

        uint32_t nextBlockSize{};
        if (!sourceView.ReadBe32(sourceOffset, nextBlockSize))
        {
            return Refuse(error, "XEX2 normal-compression next-block descriptor is truncated");
        }
        std::array<uint8_t, 20> nextBlockHash{};
        if (!sourceView.Contains(sourceOffset + sizeof(uint32_t), nextBlockHash.size()))
        {
            return Refuse(error, "XEX2 normal-compression next-block hash is truncated");
        }
        std::memcpy(nextBlockHash.data(), source + sourceOffset + sizeof(uint32_t),
                    nextBlockHash.size());

        const size_t blockEnd = sourceOffset + blockSize;
        size_t chunkOffset = sourceOffset + sizeof(Xex2CompressedBlockInfo);
        bool foundTerminator = false;
        while (chunkOffset < blockEnd)
        {
            uint16_t chunkSize{};
            if (chunkOffset + sizeof(uint16_t) > blockEnd ||
                !sourceView.ReadBe16(chunkOffset, chunkSize))
            {
                return Refuse(error, "XEX2 normal-compression chunk header is truncated");
            }
            chunkOffset += sizeof(uint16_t);
            if (chunkSize == 0)
            {
                foundTerminator = true;
                break;
            }
            if (chunkSize > blockEnd - chunkOffset)
            {
                return Refuse(error, "XEX2 normal-compression chunk exceeds its block");
            }
            if (chunkSize > sourceSize - compressed.size())
            {
                return Refuse(error, "XEX2 normal-compression chunk stream overflows");
            }
            compressed.insert(compressed.end(), source + chunkOffset,
                              source + chunkOffset + chunkSize);
            chunkOffset += chunkSize;
        }
        if (!foundTerminator)
        {
            return Refuse(error, "XEX2 normal-compression block has no chunk terminator");
        }

        sourceOffset = blockEnd;
        blockSize = nextBlockSize;
        blockHash = nextBlockHash;
    }
    if (compressed.empty())
    {
        return Refuse(error, "XEX2 normal-compression stream is empty");
    }

    result = std::make_unique<uint8_t[]>(declaredImageSize);
    if (lzxDecompress(compressed.data(), compressed.size(), result.get(), declaredImageSize,
                      windowSize, nullptr, 0) != 0)
    {
        return Refuse(error, "XEX2 normal-compression LZX stream is invalid");
    }
    return true;
}

bool MapPeSections(Image &image, std::vector<SectionSpec> &sections, std::string &error)
{
    const ByteView imageBytes(image.data.get(), image.size);
    uint32_t peOffset{};
    if (!imageBytes.ReadLe32(PeOffsetField, peOffset))
    {
        return Refuse(error, "XEX2 image has a truncated DOS header");
    }
    uint32_t signature{};
    if (!imageBytes.ReadLe32(peOffset, signature) || signature != PeSignature)
    {
        return Refuse(error, "XEX2 image has an invalid PE signature");
    }
    if (!imageBytes.Contains(peOffset, PeSignatureSize + PeFileHeaderSize))
    {
        return Refuse(error, "XEX2 image has a truncated PE file header");
    }

    uint16_t sectionCount{};
    uint16_t optionalHeaderSize{};
    const size_t fileHeaderOffset = peOffset + PeSignatureSize;
    if (!imageBytes.ReadLe16(fileHeaderOffset + 2, sectionCount) ||
        !imageBytes.ReadLe16(fileHeaderOffset + 16, optionalHeaderSize))
    {
        return Refuse(error, "XEX2 image has a truncated PE file header");
    }
    const size_t sectionTableBase = fileHeaderOffset + PeFileHeaderSize;
    if (!imageBytes.Contains(sectionTableBase, optionalHeaderSize))
    {
        return Refuse(error, "XEX2 image has a truncated PE optional header");
    }
    constexpr size_t PeSizeOfImageOffset = 56;
    if (optionalHeaderSize < PeSizeOfImageOffset + sizeof(uint32_t))
    {
        return Refuse(error, "XEX2 image PE optional header omits SizeOfImage");
    }
    uint32_t mappedImageSize{};
    if (!imageBytes.ReadLe32(sectionTableBase + PeSizeOfImageOffset, mappedImageSize) ||
        mappedImageSize < image.size)
    {
        return Refuse(error, "XEX2 image has an invalid PE SizeOfImage");
    }
    const size_t sectionTableOffset = sectionTableBase + optionalHeaderSize;
    if (!imageBytes.Contains(sectionTableOffset,
                             static_cast<size_t>(sectionCount) * PeSectionHeaderSize))
    {
        return Refuse(error, "XEX2 image has a truncated PE section table");
    }

    sections.clear();
    sections.reserve(sectionCount);
    for (size_t index = 0; index < sectionCount; ++index)
    {
        const size_t sectionOffset = sectionTableOffset + index * PeSectionHeaderSize;
        size_t nameSize = 0;
        while (nameSize < 8 && imageBytes.Data(sectionOffset)[nameSize] != 0)
        {
            ++nameSize;
        }

        uint32_t virtualSize{};
        uint32_t virtualAddress{};
        uint32_t characteristics{};
        if (!imageBytes.ReadLe32(sectionOffset + 8, virtualSize) ||
            !imageBytes.ReadLe32(sectionOffset + 12, virtualAddress) ||
            !imageBytes.ReadLe32(sectionOffset + 36, characteristics))
        {
            return Refuse(error, "XEX2 image has a truncated PE section entry");
        }
        if (virtualAddress > mappedImageSize || virtualSize > mappedImageSize - virtualAddress)
        {
            return Refuse(error, "XEX2 PE section exceeds the mapped image");
        }
        const uint64_t guestBase = static_cast<uint64_t>(image.base) + virtualAddress;
        const uint64_t guestEnd = guestBase + virtualSize;
        if (guestBase > std::numeric_limits<uint32_t>::max() ||
            guestEnd > static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) + 1)
        {
            return Refuse(error, "XEX2 PE section exceeds the 32-bit guest address space");
        }

        sections.push_back({
            std::string(reinterpret_cast<const char *>(imageBytes.Data(sectionOffset)), nameSize),
            virtualAddress,
            virtualSize,
            static_cast<uint8_t>((characteristics & PeSectionContainsCode) != 0
                                     ? SectionFlags_Code
                                     : SectionFlags_None),
        });
    }

    std::vector<const SectionSpec *> ordered;
    ordered.reserve(sections.size());
    for (const SectionSpec &section : sections)
    {
        ordered.push_back(&section);
    }
    std::sort(ordered.begin(), ordered.end(), [](const SectionSpec *lhs, const SectionSpec *rhs)
              { return lhs->virtualAddress < rhs->virtualAddress; });
    for (size_t index = 1; index < ordered.size(); ++index)
    {
        const uint64_t previousEnd = static_cast<uint64_t>(ordered[index - 1]->virtualAddress) +
                                     ordered[index - 1]->virtualSize;
        if (ordered[index]->virtualAddress < previousEnd ||
            ordered[index]->virtualAddress == ordered[index - 1]->virtualAddress)
        {
            return Refuse(error, "XEX2 PE sections overlap or share a base address");
        }
    }

    if (mappedImageSize > image.size)
    {
        auto mappedData = std::make_unique<uint8_t[]>(mappedImageSize);
        std::memcpy(mappedData.get(), image.data.get(), image.size);
        std::memset(mappedData.get() + image.size, 0, mappedImageSize - image.size);
        image.data = std::move(mappedData);
    }
    image.capacity = mappedImageSize;

    for (const SectionSpec &section : sections)
    {
        image.Map(section.name, section.virtualAddress, section.virtualSize, section.flags,
                  image.data.get() + section.virtualAddress);
    }
    return true;
}

bool ParseImportStrings(const ByteView &xex, size_t stringsOffset, size_t stringsSize,
                        uint32_t stringCount, std::vector<std::string> &strings, std::string &error)
{
    if (!xex.Contains(stringsOffset, stringsSize))
    {
        return Refuse(error, "XEX2 import string table exceeds the sealed header");
    }
    strings.clear();
    strings.reserve(stringCount);
    size_t relativeOffset = 0;
    for (uint32_t index = 0; index < stringCount; ++index)
    {
        if (relativeOffset >= stringsSize)
        {
            return Refuse(error, "XEX2 import string table has fewer names than declared");
        }
        const uint8_t *begin = xex.Data(stringsOffset + relativeOffset);
        const void *terminator = std::memchr(begin, 0, stringsSize - relativeOffset);
        if (terminator == nullptr)
        {
            return Refuse(error, "XEX2 import string is not terminated within its table");
        }
        const size_t length = static_cast<const uint8_t *>(terminator) - begin;
        strings.emplace_back(reinterpret_cast<const char *>(begin), length);
        const size_t consumed = relativeOffset + length + 1;
        if (consumed > std::numeric_limits<size_t>::max() - 3)
        {
            return Refuse(error, "XEX2 import string padding overflows host size");
        }
        relativeOffset = (consumed + 3) & ~size_t(3);
        if (relativeOffset > stringsSize)
        {
            return Refuse(error, "XEX2 import string padding exceeds its table");
        }
    }
    return true;
}

bool ParseImports(const ByteView &xex, size_t importsOffset, size_t headerSize, Image &image,
                  std::string &error)
{
    uint32_t importsSize{};
    uint32_t stringsSize{};
    uint32_t stringCount{};
    if (!xex.ReadBe32(importsOffset, importsSize) ||
        !xex.ReadBe32(importsOffset + 4, stringsSize) ||
        !xex.ReadBe32(importsOffset + 8, stringCount))
    {
        return Refuse(error, "XEX2 import header is truncated");
    }
    if (importsSize < sizeof(Xex2ImportHeader) || importsSize > headerSize - importsOffset)
    {
        return Refuse(error, "XEX2 import header exceeds the sealed header");
    }
    if (stringsSize > importsSize - sizeof(Xex2ImportHeader))
    {
        return Refuse(error, "XEX2 import string table exceeds its optional header");
    }

    std::vector<std::string> strings;
    const size_t stringsOffset = importsOffset + sizeof(Xex2ImportHeader);
    if (!ParseImportStrings(xex, stringsOffset, stringsSize, stringCount, strings, error))
    {
        return false;
    }

    const size_t importsEnd = importsOffset + importsSize;
    size_t libraryOffset = stringsOffset + stringsSize;
    std::unordered_set<uint32_t> descriptorAddresses;
    std::set<std::pair<std::string, uint32_t>> logicalIdentities;
    std::vector<RawImport> allRawImports;
    std::vector<uint32_t> functionStubs;

    while (libraryOffset < importsEnd)
    {
        if (ImportLibraryHeaderSize > importsEnd - libraryOffset)
        {
            return Refuse(error, "XEX2 import library header is truncated");
        }

        uint32_t librarySize{};
        uint16_t nameIndexValue{};
        uint16_t descriptorCount{};
        if (!xex.ReadBe32(libraryOffset, librarySize) ||
            !xex.ReadBe16(libraryOffset + 36, nameIndexValue) ||
            !xex.ReadBe16(libraryOffset + 38, descriptorCount))
        {
            return Refuse(error, "XEX2 import library header is truncated");
        }
        if (librarySize < ImportLibraryHeaderSize || librarySize > importsEnd - libraryOffset)
        {
            return Refuse(error, "XEX2 import library size exceeds its optional header");
        }
        const size_t descriptorBytes =
            static_cast<size_t>(descriptorCount) * sizeof(Xex2ImportDescriptor);
        if (descriptorBytes > librarySize - ImportLibraryHeaderSize)
        {
            return Refuse(error, "XEX2 import descriptor table exceeds its library");
        }

        const size_t nameIndex = nameIndexValue & 0xffU;
        if (nameIndex >= strings.size())
        {
            return Refuse(error, "XEX2 import library name index is outside the string table");
        }
        const std::string &libraryName = strings[nameIndex];
        const auto *exportNames = FindExportNames(libraryName);

        std::vector<RawImport> rawImports;
        rawImports.reserve(descriptorCount);
        const size_t descriptorOffset = libraryOffset + ImportLibraryHeaderSize;
        for (size_t index = 0; index < descriptorCount; ++index)
        {
            uint32_t address{};
            if (!xex.ReadBe32(descriptorOffset + index * sizeof(Xex2ImportDescriptor), address))
            {
                return Refuse(error, "XEX2 import descriptor table is truncated");
            }
            if (!descriptorAddresses.insert(address).second)
            {
                return Refuse(error, "XEX2 import descriptor address is duplicated");
            }

            uint32_t hostValue{};
            if (!ReadImageBe32(image, address, hostValue))
            {
                return Refuse(error, "XEX2 import record is outside a mapped PE section");
            }
            const uint8_t type = static_cast<uint8_t>((hostValue >> 24U) & 0xffU);
            if (type != XEX_THUNK_VARIABLE && type != XEX_THUNK_FUNCTION)
            {
                return Refuse(error, "XEX2 import record has an unknown thunk type");
            }
            rawImports.push_back({address, hostValue, hostValue & 0xffffU, type});
        }

        for (size_t index = 0; index < rawImports.size(); ++index)
        {
            const RawImport &record = rawImports[index];
            if (record.type == XEX_THUNK_FUNCTION)
            {
                return Refuse(error, "XEX2 function thunk lacks an adjacent variable record");
            }

            const bool followedByFunction =
                index + 1 < rawImports.size() && rawImports[index + 1].type == XEX_THUNK_FUNCTION;
            if (followedByFunction && rawImports[index + 1].ordinal != record.ordinal)
            {
                return Refuse(error, "XEX2 adjacent import record and function thunk disagree");
            }
            if (!logicalIdentities.insert({libraryName, record.ordinal}).second)
            {
                return Refuse(error, "XEX2 repeats a library-and-ordinal import identity");
            }

            const std::string name = ExportName(exportNames, record.ordinal);
            if (followedByFunction)
            {
                const RawImport &thunk = rawImports[index + 1];
                if (image.FindRange(thunk.address, ImportFunctionStubSize) == nullptr)
                {
                    return Refuse(error, "XEX2 function thunk does not have 16 mapped bytes");
                }
                image.imports.push_back({name, libraryName, thunk.address, record.address,
                                         record.ordinal, ImportKind::Function});
                if (!name.empty())
                {
                    image.symbols.insert(
                        {name, thunk.address, ImportFunctionStubSize, Symbol_Function});
                }
                functionStubs.push_back(thunk.address);
                ++index;
            }
            else
            {
                image.imports.push_back({name, libraryName, record.address, record.address,
                                         record.ordinal, ImportKind::Variable});
                image.importVariables.push_back(
                    {name, libraryName, record.address, record.ordinal});
            }
        }

        allRawImports.insert(allRawImports.end(), rawImports.begin(), rawImports.end());
        libraryOffset += librarySize;
    }

    for (const RawImport &rawImport : allRawImports)
    {
        void *destination = image.FindRange(rawImport.address, sizeof(uint32_t));
        std::memcpy(destination, &rawImport.hostValue, sizeof(rawImport.hostValue));
    }
    constexpr std::array<uint32_t, 4> FunctionStubWords = {
        0x00000060U,
        0x00000060U,
        0x00000060U,
        0x2000804EU,
    };
    for (uint32_t address : functionStubs)
    {
        void *destination = image.FindRange(address, ImportFunctionStubSize);
        std::memcpy(destination, FunctionStubWords.data(), ImportFunctionStubSize);
    }
    return true;
}

bool TryLoadXexImpl(const uint8_t *data, size_t dataSize, Image &loadedImage,
                    Xex2ExecutionMetadata &loadedMetadata, std::string &error)
{
    if (data == nullptr || dataSize < sizeof(Xex2Header))
    {
        return Refuse(error, "XEX2 fixed header is truncated");
    }
    const ByteView xex(data, dataSize);

    uint32_t magic{};
    uint32_t headerSizeValue{};
    uint32_t securityOffsetValue{};
    uint32_t headerCountValue{};
    if (!xex.ReadBe32(offsetof(Xex2Header, magic), magic) ||
        !xex.ReadBe32(offsetof(Xex2Header, headerSize), headerSizeValue) ||
        !xex.ReadBe32(offsetof(Xex2Header, securityOffset), securityOffsetValue) ||
        !xex.ReadBe32(offsetof(Xex2Header, headerCount), headerCountValue))
    {
        return Refuse(error, "XEX2 fixed header is truncated");
    }
    if (magic != Xex2Magic)
    {
        return Refuse(error, "input is not an XEX2 executable");
    }

    const size_t headerSize = headerSizeValue;
    const size_t headerCount = headerCountValue;
    if (headerCount >
        (std::numeric_limits<size_t>::max() - sizeof(Xex2Header)) / sizeof(Xex2OptHeader))
    {
        return Refuse(error, "XEX2 optional-header count overflows host size");
    }
    const size_t tableEnd = sizeof(Xex2Header) + headerCount * sizeof(Xex2OptHeader);
    if (tableEnd > headerSize || !xex.Contains(0, headerSize))
    {
        return Refuse(error, "XEX2 optional-header table is outside the sealed header");
    }

    std::unordered_map<uint32_t, OptionalHeaderValue> optionalHeaders;
    optionalHeaders.reserve(headerCount);
    for (size_t index = 0; index < headerCount; ++index)
    {
        const size_t offset = sizeof(Xex2Header) + index * sizeof(Xex2OptHeader);
        uint32_t key{};
        uint32_t value{};
        if (!xex.ReadBe32(offset, key) || !xex.ReadBe32(offset + sizeof(uint32_t), value))
        {
            return Refuse(error, "XEX2 optional-header table is truncated");
        }
        if (!optionalHeaders.emplace(key, OptionalHeaderValue{value}).second)
        {
            return Refuse(error, "XEX2 optional-header key is duplicated");
        }
    }

    auto getOffset = [&](uint32_t key, size_t minimumSize, bool required, size_t &offset) -> bool
    {
        const auto found = optionalHeaders.find(key);
        if (found == optionalHeaders.end())
        {
            if (required)
            {
                error = "XEX2 required optional header is missing";
                return false;
            }
            offset = 0;
            return true;
        }
        offset = found->second.value;
        if (offset < tableEnd || offset > headerSize || minimumSize > headerSize - offset)
        {
            error = "XEX2 optional header points outside the sealed header";
            return false;
        }
        return true;
    };

    const size_t securityOffset = securityOffsetValue;
    if (securityOffset < tableEnd || securityOffset > headerSize ||
        sizeof(Xex2SecurityInfo) > headerSize - securityOffset)
    {
        return Refuse(error, "XEX2 security header is outside the sealed header");
    }
    uint32_t securityHeaderSize{};
    if (!xex.ReadBe32(securityOffset + offsetof(Xex2SecurityInfo, headerSize),
                      securityHeaderSize) ||
        securityHeaderSize < sizeof(Xex2SecurityInfo) ||
        securityHeaderSize > headerSize - securityOffset)
    {
        return Refuse(error, "XEX2 security header size exceeds the sealed header");
    }

    Xex2SecurityInfo securityInfo{};
    std::memcpy(&securityInfo, xex.Data(securityOffset), sizeof(securityInfo));

    size_t executionOffset{};
    if (!getOffset(XEX_HEADER_EXECUTION_INFO, sizeof(Xex2ExecutionInfo), true, executionOffset))
    {
        return false;
    }
    Xex2ExecutionMetadata metadata{};
    if (!xex.ReadBe32(executionOffset, metadata.mediaId) ||
        !xex.ReadBe32(executionOffset + 4, metadata.version) ||
        !xex.ReadBe32(executionOffset + 8, metadata.baseVersion) ||
        !xex.ReadBe32(executionOffset + 12, metadata.titleId) ||
        !xex.ReadU8(executionOffset + 16, metadata.platform) ||
        !xex.ReadU8(executionOffset + 17, metadata.executableTable) ||
        !xex.ReadU8(executionOffset + 18, metadata.discNumber) ||
        !xex.ReadU8(executionOffset + 19, metadata.discCount) ||
        !xex.ReadBe32(executionOffset + 20, metadata.savegameId))
    {
        return Refuse(error, "XEX2 execution-info header is truncated");
    }

    size_t formatOffset{};
    if (!getOffset(XEX_HEADER_FILE_FORMAT_INFO, sizeof(Xex2OptFileFormatInfo), true, formatOffset))
    {
        return false;
    }
    uint32_t formatSizeValue{};
    uint16_t encryptionType{};
    uint16_t compressionType{};
    if (!xex.ReadBe32(formatOffset, formatSizeValue) ||
        !xex.ReadBe16(formatOffset + 4, encryptionType) ||
        !xex.ReadBe16(formatOffset + 6, compressionType))
    {
        return Refuse(error, "XEX2 file-format header is truncated");
    }
    const size_t formatSize = formatSizeValue;
    if (formatSize < sizeof(Xex2OptFileFormatInfo) || formatSize > headerSize - formatOffset)
    {
        return Refuse(error, "XEX2 file-format header exceeds the sealed header");
    }

    std::unique_ptr<uint8_t[]> imageData;
    if (!DecompressImage(xex, headerSize, formatOffset, formatSize, encryptionType, compressionType,
                         securityInfo, imageData, error))
    {
        return false;
    }

    Image image{};
    image.data = std::move(imageData);
    image.size = securityInfo.imageSize;
    image.base = securityInfo.loadAddress;
    const auto imageBase = optionalHeaders.find(XEX_HEADER_IMAGE_BASE_ADDRESS);
    if (imageBase != optionalHeaders.end())
    {
        image.base = imageBase->second.value;
    }
    const auto entryPoint = optionalHeaders.find(XEX_HEADER_ENTRY_POINT);
    if (entryPoint != optionalHeaders.end())
    {
        image.entry_point = entryPoint->second.value;
    }

    std::vector<SectionSpec> sections;
    if (!MapPeSections(image, sections, error))
    {
        return false;
    }

    size_t importsOffset{};
    if (!getOffset(XEX_HEADER_IMPORT_LIBRARIES, sizeof(Xex2ImportHeader), false, importsOffset))
    {
        return false;
    }
    if (importsOffset != 0 && !ParseImports(xex, importsOffset, headerSize, image, error))
    {
        return false;
    }

    loadedImage = std::move(image);
    loadedMetadata = metadata;
    error.clear();
    return true;
}
} // namespace

bool TryLoadXex(const uint8_t *data, size_t dataSize, Image &image, Xex2ExecutionMetadata &metadata,
                std::string &error)
{
    image = {};
    metadata = {};
    error.clear();
    try
    {
        return TryLoadXexImpl(data, dataSize, image, metadata, error);
    }
    catch (const std::bad_alloc &)
    {
        image = {};
        metadata = {};
        error = "XEX2 allocation failed while validating the image";
        return false;
    }
}

Image Xex2LoadImage(const uint8_t *data, size_t dataSize)
{
    Image image{};
    Xex2ExecutionMetadata metadata{};
    std::string error;
    if (!TryLoadXex(data, dataSize, image, metadata, error))
    {
        return {};
    }
    return image;
}
