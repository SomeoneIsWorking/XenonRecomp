#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

#include <byteswap.h>
#include <function.h>
#include <symbol_table.h>

#include "data_range.h"
#include "function_scan.h"

namespace
{
constexpr std::size_t kGapStart = 0x82001000;
constexpr std::size_t kOwnerStart = kGapStart + 8;
constexpr std::size_t kSectionEnd = kGapStart + 0x100;

void Require(bool condition, const char *message)
{
    if (!condition)
    {
        std::cerr << "function scan test failed: " << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}
} // namespace

int main()
{
    SymbolTable symbols;
    symbols.emplace("data", kGapStart + 4, 4, Symbol_Comment);
    symbols.emplace("owner", kOwnerStart, 0x40, Symbol_Function);

    const auto limit = FunctionAnalysisLimit(kGapStart, kSectionEnd, symbols);
    Require(limit == 8, "gap analysis crossed the next function symbol");

    // The first two words are the exact data-decoding shape that preceded all
    // ten affected MUA .pdata owners. The third word is the owner's mflr r12.
    // Analyze must not consume that third word when its byte limit is eight.
    const std::uint32_t words[] = {
        ByteSwap<std::uint32_t>(0x82855FC0),
        ByteSwap<std::uint32_t>(0x82002E40),
        ByteSwap<std::uint32_t>(0x7D8802A6),
    };
    const auto gap = Function::Analyze(words, limit, kGapStart);
    Require(gap.base == kGapStart, "gap base changed");
    Require(gap.size == 8, "Function::Analyze read through its exclusive byte limit");
    const auto oneWord = Function::Analyze(words, 4, kGapStart);
    Require(oneWord.size == 4, "four-byte gap read the next word");
    const auto empty = Function::Analyze(nullptr, 0, kGapStart);
    Require(empty.size == 0, "empty gap was not empty");

    SymbolTable noFunctions;
    noFunctions.emplace("comment", kGapStart + 4, 4, Symbol_Comment);
    Require(FunctionAnalysisLimit(kGapStart, kSectionEnd, noFunctions) == 0x100,
            "non-function symbol incorrectly bounded analysis");
    Require(FunctionAnalysisLimit(kSectionEnd, kSectionEnd, noFunctions) == 0,
            "empty section tail was not empty");
    try
    {
        (void)AnalyzeFunctionGap(words, kSectionEnd, kSectionEnd, noFunctions, {});
        Require(false, "zero-byte analysis was accepted");
    }
    catch (const std::runtime_error &)
    {
    }

    const std::vector<RecompilerDataRange> startsInData{{kGapStart, 8}};
    try
    {
        (void)AnalyzeFunctionGap(words, kGapStart, kSectionEnd, noFunctions, startsInData);
        Require(false, "analysis starting inside data was accepted");
    }
    catch (const std::runtime_error &)
    {
    }

    const std::uint32_t branchWords[] = {
        ByteSwap<std::uint32_t>(0x4800000D),
        ByteSwap<std::uint32_t>(0x4800000D),
    };
    const std::vector<RecompilerDataRange> firstWordIsData{{kGapStart, 4}};
    const auto targets = DiscoverBranchAndLinkTargets(branchWords, kGapStart, 8, firstWordIsData);
    Require(targets.size() == 1 && targets[0] == kGapStart + 0x10,
            "data word that decoded as BL was treated as an instruction");

    // A bounded leaf gap may tail-branch to a function beyond the next
    // authoritative symbol. The analyzer must discard that external edge and
    // resume the local path that was pending on its work stack.
    const std::uint32_t forwardTailWords[] = {
        ByteSwap<std::uint32_t>(0x41820010), // beq +0x10
        ByteSwap<std::uint32_t>(0x38600001), // li r3,1
        ByteSwap<std::uint32_t>(0x38600002), // li r3,2
        ByteSwap<std::uint32_t>(0x4E800020), // blr
        ByteSwap<std::uint32_t>(0x480000F0), // b +0xf0 (outside the gap)
    };
    const auto forwardTail =
        Function::Analyze(forwardTailWords, sizeof(forwardTailWords), kGapStart);
    const auto pendingLocal = forwardTail.SearchBlock(kGapStart + 4);
    Require(pendingLocal != static_cast<std::size_t>(-1),
            "external forward tail discarded a pending local block");
    Require(forwardTail.blocks[pendingLocal].size == 12,
            "pending local block was not analyzed through its return");

    // The taken arm of a conditional branch may itself leave the bounded gap.
    // That arm is an external edge, while the in-range fallthrough still owns
    // the bytes that follow the branch.
    const std::uint32_t externalConditionalWords[] = {
        ByteSwap<std::uint32_t>(0x41820100), // beq +0x100 (outside the gap)
        ByteSwap<std::uint32_t>(0x38600001), // li r3,1
        ByteSwap<std::uint32_t>(0x4E800020), // blr
    };
    const auto externalConditional =
        Function::Analyze(externalConditionalWords, sizeof(externalConditionalWords), kGapStart);
    Require(externalConditional.size == sizeof(externalConditionalWords),
            "external conditional arm truncated the in-range fallthrough");
    Require(externalConditional.SearchBlock(kGapStart + 0x100) == static_cast<std::size_t>(-1),
            "conditional branch invented an out-of-range block");

    const std::uint32_t localConditionalWords[] = {
        ByteSwap<std::uint32_t>(0x41820010), // beq +0x10
        ByteSwap<std::uint32_t>(0x38600001), // li r3,1
        ByteSwap<std::uint32_t>(0x38600003), // li r3,3
        ByteSwap<std::uint32_t>(0x4E800020), // blr
        ByteSwap<std::uint32_t>(0x38600002), // li r3,2
        ByteSwap<std::uint32_t>(0x4E800020), // blr
    };
    const auto localConditional =
        Function::Analyze(localConditionalWords, sizeof(localConditionalWords), kGapStart);
    Require(localConditional.SearchBlock(kGapStart + 4) != static_cast<std::size_t>(-1) &&
                localConditional.SearchBlock(kGapStart + 0x10) != static_cast<std::size_t>(-1),
            "in-range conditional control flow regressed");

    Function disjoint{kGapStart, 4};
    disjoint.AbsorbCode(Function{kGapStart + 0x10, 4});
    Require(disjoint.size == 0x14, "disjoint function envelope did not reach its last block");
    Require(disjoint.ContainsAddress(kGapStart) && disjoint.ContainsAddress(kGapStart + 0x10),
            "disjoint executable blocks lost owned code");
    Require(!disjoint.ContainsAddress(kGapStart + 4),
            "data hole inside a function envelope was classified as executable code");
    Require(disjoint.ExecutableBlocks().size() == 2,
            "normalization joined executable blocks across a data hole");

    std::cout << "function scan test passed: boundaries cap analysis and BL discovery\n";
    return EXIT_SUCCESS;
}
