#pragma once

#include <cstddef>
#include <vector>

class SymbolTable;
struct Function;
struct RecompilerDataRange;

// Return the number of bytes a gap scan may inspect without crossing the next
// authoritative function symbol or the containing code section.
std::size_t FunctionAnalysisLimit(std::size_t start, std::size_t sectionEnd,
                                  const SymbolTable &symbols);

Function AnalyzeFunctionGap(const void *code, std::size_t start, std::size_t sectionEnd,
                            const SymbolTable &symbols,
                            const std::vector<RecompilerDataRange> &dataRanges);

std::vector<std::size_t>
DiscoverBranchAndLinkTargets(const void *code, std::size_t sectionBase, std::size_t sectionSize,
                             const std::vector<RecompilerDataRange> &dataRanges);
