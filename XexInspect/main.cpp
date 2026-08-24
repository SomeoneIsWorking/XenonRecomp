#include "inspect.h"

#include <file.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string_view>

namespace
{
int Usage(const char *executable)
{
    std::cerr << "usage: " << executable << " INPUT.xex --image-out IMAGE.bin\n";
    return 2;
}

bool WriteImage(const std::filesystem::path &path, const std::vector<uint8_t> &bytes)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char *>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    return output.good();
}
} // namespace

int main(int argc, char **argv)
{
    if (argc != 4 || std::string_view(argv[2]) != "--image-out")
    {
        return Usage(argv[0]);
    }

    const std::filesystem::path inputPath(argv[1]);
    const std::filesystem::path imagePath(argv[3]);
    const std::vector<uint8_t> xex = LoadFile(inputPath);
    if (xex.empty())
    {
        std::cerr << "xex-inspect: REFUSING: input is missing, unreadable, or empty: " << inputPath
                  << '\n';
        return 2;
    }

    XexInspection inspection;
    std::string error;
    if (!InspectXex(xex, inspection, error))
    {
        std::cerr << "xex-inspect: REFUSING: " << error << '\n';
        return 2;
    }
    if (!WriteImage(imagePath, inspection.imageBytes))
    {
        std::cerr << "xex-inspect: REFUSING: cannot write exact image bytes: " << imagePath << '\n';
        return 2;
    }

    std::cout << RenderInspectionJson(inspection);
    return 0;
}
