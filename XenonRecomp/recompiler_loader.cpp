#include "pch.h"
#include "recompiler.h"

#include <sha256.h>
#include <xex_patcher.h>

bool Recompiler::LoadConfig(const std::string_view &configFilePath)
{
    config.Load(configFilePath);

    std::error_code directoryError;
    std::filesystem::create_directories(
        std::filesystem::path(config.directoryPath) / config.outDirectoryPath, directoryError);
    if (directoryError)
    {
        fmt::println("ERROR: Unable to create output directory: {}", directoryError.message());
        return false;
    }

    std::vector<uint8_t> file;
    if (!config.patchedFilePath.empty())
        file = LoadFile((config.directoryPath + config.patchedFilePath).c_str());

    if (file.empty())
    {
        file = LoadFile((config.directoryPath + config.filePath).c_str());

        if (!config.patchFilePath.empty())
        {
            const auto patchFile = LoadFile((config.directoryPath + config.patchFilePath).c_str());
            if (!patchFile.empty())
            {
                std::vector<uint8_t> outBytes;
                const auto result = XexPatcher::apply(file.data(), file.size(), patchFile.data(),
                                                      patchFile.size(), outBytes, false);
                if (result == XexPatcher::Result::Success)
                {
                    std::exchange(file, outBytes);

                    if (!config.patchedFilePath.empty())
                    {
                        std::ofstream stream(config.directoryPath + config.patchedFilePath,
                                             std::ios::binary);
                        if (stream.good())
                        {
                            stream.write(reinterpret_cast<const char *>(file.data()), file.size());
                            stream.close();
                        }
                    }
                }
                else
                {
                    fmt::print("ERROR: Unable to apply the patch file, ");
                    switch (result)
                    {
                    case XexPatcher::Result::XexFileUnsupported:
                        fmt::println("XEX file unsupported");
                        break;
                    case XexPatcher::Result::XexFileInvalid:
                        fmt::println("XEX file invalid");
                        break;
                    case XexPatcher::Result::PatchFileInvalid:
                        fmt::println("patch file invalid");
                        break;
                    case XexPatcher::Result::PatchIncompatible:
                        fmt::println("patch incompatible");
                        break;
                    case XexPatcher::Result::PatchFailed:
                        fmt::println("patch failed");
                        break;
                    case XexPatcher::Result::PatchUnsupported:
                        fmt::println("patch unsupported");
                        break;
                    default:
                        fmt::println("reason unknown");
                        break;
                    }
                    return false;
                }
            }
            else
            {
                fmt::println("ERROR: Unable to load the patch file");
                return false;
            }
        }
    }

    image = Image::ParseImage(file.data(), file.size());
    if (image.data == nullptr || image.size == 0)
    {
        fmt::println("ERROR: Unable to load a valid executable image");
        return false;
    }

    std::string digestError;
    if (!ComputeSha256(file.data(), file.size(), xexDigest, digestError) ||
        !ComputeSha256(image.data.get(), image.size, imageDigest, digestError))
    {
        fmt::println("ERROR: Unable to fingerprint executable: {}", digestError);
        return false;
    }
    return true;
}
