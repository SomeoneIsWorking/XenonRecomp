#include "function_scan.h"

#include "data_range.h"
#include <cstdint>
#include <byteswap.h>
#include <disasm.h>
#include <function.h>
#include <stdexcept>
#include <symbol_table.h>

#include <fmt/format.h>

std::size_t FunctionAnalysisLimit(std::size_t start, std::size_t sectionEnd,
                                  const SymbolTable &symbols)
{
    if (start >= sectionEnd)
    {
        return 0;
    }

    for (auto symbol = symbols.upper_bound(start); symbol != symbols.end(); ++symbol)
    {
        if (symbol->address >= sectionEnd)
        {
            break;
        }
        if (symbol->type == Symbol_Function)
        {
            return symbol->address - start;
        }
    }

    return sectionEnd - start;
}

Function AnalyzeFunctionGap(const void *code, std::size_t start, std::size_t sectionEnd,
                            const SymbolTable &symbols,
                            const std::vector<RecompilerDataRange> &dataRanges)
{
    if (DataRangeContaining(dataRanges, start) != nullptr)
    {
        throw std::runtime_error(
            fmt::format("function analysis starts inside a data range at 0x{:X}", start));
    }
    auto end = start + FunctionAnalysisLimit(start, sectionEnd, symbols);
    end = NextDataRangeStart(dataRanges, start, end);
    const auto limit = end - start;
    if (limit == 0)
    {
        throw std::runtime_error(fmt::format("zero-byte function gap at 0x{:X}", start));
    }

    auto function = Function::Analyze(code, limit, start);
    if (function.size == 0 || function.size > limit)
    {
        throw std::runtime_error(
            fmt::format("function gap at 0x{:X} analyzed 0x{:X} of bounded 0x{:X} bytes", start,
                        function.size, limit));
    }
    return function;
}

std::vector<std::size_t>
DiscoverBranchAndLinkTargets(const void *code, std::size_t sectionBase, std::size_t sectionSize,
                             const std::vector<RecompilerDataRange> &dataRanges)
{
    std::vector<std::size_t> targets;
    if (sectionSize < sizeof(std::uint32_t))
    {
        return targets;
    }

    const auto *bytes = static_cast<const std::uint8_t *>(code);
    for (std::size_t offset = 0; offset <= sectionSize - sizeof(std::uint32_t);)
    {
        const auto address = sectionBase + offset;
        if (const auto skip = DataRangeScanSkip(dataRanges, address))
        {
            offset += skip;
            continue;
        }

        const auto instruction = ByteSwap(*reinterpret_cast<const std::uint32_t *>(bytes + offset));
        if (PPC_OP(instruction) == PPC_OP_B && PPC_BL(instruction))
        {
            targets.push_back(address + PPC_BI(instruction));
        }
        offset += sizeof(std::uint32_t);
    }
    return targets;
}
