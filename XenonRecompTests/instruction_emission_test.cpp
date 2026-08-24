#include "recompiler.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>

namespace
{
constexpr std::uint32_t kFunctionBase = 0x1000;
constexpr std::uint32_t kSwitchBase = 0x2000;
constexpr std::size_t kSyntheticCodeSize = 0x100;

bool Contains(std::string_view text, std::string_view fragment);

struct alignas(std::uint32_t) EncodedInstruction
{
    std::array<std::uint8_t, 4> bytes;
};

EncodedInstruction Encode(const std::uint32_t instruction)
{
    return {
        {{static_cast<std::uint8_t>(instruction >> 24),
          static_cast<std::uint8_t>(instruction >> 16), static_cast<std::uint8_t>(instruction >> 8),
          static_cast<std::uint8_t>(instruction)}}};
}

std::uint32_t EncodeXForm(const std::uint32_t rt, const std::uint32_t ra, const std::uint32_t rb,
                          const std::uint32_t xo)
{
    return (31U << 26U) | (rt << 21U) | (ra << 16U) | (rb << 11U) | (xo << 1U);
}

std::uint32_t EncodeConditionBranch(const std::uint32_t bo, const std::uint32_t bi,
                                    const std::int16_t displacement)
{
    return (16U << 26U) | (bo << 21U) | (bi << 16U) |
           (static_cast<std::uint16_t>(displacement) & 0xFFFCU);
}

std::uint32_t EncodeBranch(const std::uint32_t source, const std::uint32_t target)
{
    return 0x48000000U | ((target - source) & 0x03FFFFFCU);
}

void SetWord(Recompiler &recompiler, const std::uint32_t address, const std::uint32_t word)
{
    auto *bytes = recompiler.image.data.get() + address - recompiler.image.base;
    bytes[0] = static_cast<std::uint8_t>(word >> 24);
    bytes[1] = static_cast<std::uint8_t>(word >> 16);
    bytes[2] = static_cast<std::uint8_t>(word >> 8);
    bytes[3] = static_cast<std::uint8_t>(word);
}

void AddFunction(Recompiler &recompiler, const std::uint32_t address, const std::uint32_t size,
                 const bool authoritative = false)
{
    recompiler.functions.emplace_back(address, size);
    recompiler.image.symbols.emplace("sub_" + std::to_string(address), address, size,
                                     Symbol_Function);
    if (authoritative)
    {
        recompiler.authoritativeFunctionStarts.emplace(address);
    }
}

Recompiler MakeInlineSwitchFixture(const bool seedCaseFunctions = true)
{
    constexpr std::uint32_t kTable = kSwitchBase + 8;
    constexpr std::uint32_t kCase0 = kTable + 0x10;
    constexpr std::uint32_t kCase1 = kCase0 + 4;
    constexpr std::uint32_t kCase2 = kCase1 + 4;
    constexpr std::uint32_t kCase3 = kCase2 + 4;
    constexpr std::uint32_t kUnrelated = kCase3 + 4;
    constexpr std::uint32_t kSharedEpilogue = kSwitchBase + 0x40;

    Recompiler recompiler;
    recompiler.image.base = kSwitchBase;
    recompiler.image.size = kSyntheticCodeSize;
    recompiler.image.data = std::make_unique<std::uint8_t[]>(kSyntheticCodeSize);
    recompiler.image.Map(".text", 0, kSyntheticCodeSize, SectionFlags_Code,
                         recompiler.image.data.get());

    SetWord(recompiler, kSwitchBase, 0x7C0903A6);     // mtctr r0
    SetWord(recompiler, kSwitchBase + 4, 0x4E800420); // bctr
    for (std::uint32_t address = kTable; address < kCase0; address += 4)
    {
        SetWord(recompiler, address, 0x38630001); // addi r3,r3,1: data, never code
    }
    SetWord(recompiler, kCase0, EncodeBranch(kCase0, kSharedEpilogue));
    SetWord(recompiler, kCase1, EncodeBranch(kCase1, kSharedEpilogue));
    SetWord(recompiler, kCase2, EncodeBranch(kCase2, kSharedEpilogue));
    SetWord(recompiler, kCase3, EncodeBranch(kCase3, kSharedEpilogue));
    SetWord(recompiler, kUnrelated, 0x4E800020);      // blr
    SetWord(recompiler, kSharedEpilogue, 0x4E800020); // blr

    recompiler.config.dataRanges.push_back({kTable, 0x10});
    recompiler.config.switchTables.emplace(
        kSwitchBase, RecompilerSwitchTable{3, {kCase0, kCase1, kCase2, kCase3}});

    AddFunction(recompiler, kSwitchBase, 8, true);
    if (seedCaseFunctions)
    {
        AddFunction(recompiler, kCase0, 4);
        AddFunction(recompiler, kCase1, 4);
        AddFunction(recompiler, kCase2, 4);
        AddFunction(recompiler, kCase3, 4);
    }
    AddFunction(recompiler, kUnrelated, 4, true);
    AddFunction(recompiler, kSharedEpilogue, 4);
    return recompiler;
}

bool RefusesSwitchLayout(Recompiler recompiler, const std::string_view expected)
{
    try
    {
        recompiler.ResolveSwitchFunctionOwnership();
    }
    catch (const std::runtime_error &error)
    {
        return Contains(error.what(), expected);
    }
    std::cerr << "invalid switch layout was accepted; expected: " << expected << '\n';
    return false;
}

bool Contains(const std::string_view text, const std::string_view fragment)
{
    if (text.find(fragment) != std::string_view::npos)
    {
        return true;
    }

    std::cerr << "expected emission fragment missing:\n" << fragment << "actual:\n" << text;
    return false;
}

bool Omits(const std::string_view text, const std::string_view fragment)
{
    if (text.find(fragment) == std::string_view::npos)
    {
        return true;
    }

    std::cerr << "unexpected emission fragment present:\n" << fragment << "actual:\n" << text;
    return false;
}

bool Decode(const EncodedInstruction &encoded, ppc_insn &instruction)
{
    return ppc::Disassemble(encoded.bytes.data(), encoded.bytes.size(), kFunctionBase,
                            instruction) == 4 &&
           instruction.opcode != nullptr;
}

std::string Emit(const EncodedInstruction &encoded, const Function &function, ppc_insn &instruction)
{
    Recompiler recompiler;
    auto switchTable = recompiler.config.switchTables.end();
    RecompilerLocalVariables localVariables;
    CSRState csrState = CSRState::Unknown;
    const auto *data = reinterpret_cast<const std::uint32_t *>(encoded.bytes.data());

    if (!Decode(encoded, instruction) ||
        !recompiler.Recompile(function, kFunctionBase, instruction, data, switchTable,
                              localVariables, csrState))
    {
        return {};
    }
    return recompiler.out;
}

bool TestLhbrxDecoderAndEmission()
{
    constexpr std::uint32_t kLhbrxXo = 790;
    const auto indexed = Encode(EncodeXForm(7, 8, 9, kLhbrxXo));
    ppc_insn instruction{};
    const auto emitted = Emit(indexed, Function{kFunctionBase, 4}, instruction);

    if (instruction.opcode == nullptr || instruction.opcode->id != PPC_INST_LHBRX ||
        instruction.operands[0] != 7 || instruction.operands[1] != 8 ||
        instruction.operands[2] != 9)
    {
        std::cerr << "lhbrx did not decode to RT=7, RA=8, RB=9\n";
        return false;
    }

    const auto zeroBase = Encode(EncodeXForm(7, 0, 9, kLhbrxXo));
    ppc_insn zeroBaseInstruction{};
    const auto zeroBaseEmission = Emit(zeroBase, Function{kFunctionBase, 4}, zeroBaseInstruction);

    return Contains(emitted, "ctx.r7.u64 = __builtin_bswap16(PPC_LOAD_U16(ctx.r8.u32 + "
                             "ctx.r9.u32));") &&
           Contains(zeroBaseEmission,
                    "ctx.r7.u64 = __builtin_bswap16(PPC_LOAD_U16(ctx.r9.u32));") &&
           Omits(zeroBaseEmission, "ctx.r0.u32");
}

bool TestLhzxDoesNotDecodeOrEmitAsLhbrx()
{
    constexpr std::uint32_t kLhzxXo = 279;
    const auto encoded = Encode(EncodeXForm(7, 8, 9, kLhzxXo));
    ppc_insn instruction{};
    const auto emitted = Emit(encoded, Function{kFunctionBase, 4}, instruction);

    return instruction.opcode != nullptr && instruction.opcode->id == PPC_INST_LHZX &&
           Omits(emitted, "__builtin_bswap16") &&
           Contains(emitted, "ctx.r7.u64 = PPC_LOAD_U16(ctx.r8.u32 + ctx.r9.u32);");
}

bool TestBsoDecoderAndEmission()
{
    constexpr std::uint32_t kBranchIfTrue = 12;
    constexpr std::uint32_t kCr2SummaryOverflowBit = 11;
    const auto encoded = Encode(EncodeConditionBranch(kBranchIfTrue, kCr2SummaryOverflowBit, 8));
    ppc_insn instruction{};
    const auto emitted = Emit(encoded, Function{kFunctionBase, 12}, instruction);

    if (instruction.opcode == nullptr || instruction.opcode->id != PPC_INST_BSO ||
        instruction.operands[0] != 2 || instruction.operands[1] != kFunctionBase + 8)
    {
        std::cerr << "bso did not decode to CR2 and the relative target\n";
        return false;
    }

    return Contains(emitted, "if (ctx.cr2.so) goto loc_1008;") && Omits(emitted, "!ctx.cr2.so") &&
           Omits(emitted, "ctx.cr2.eq");
}

bool TestBnsDoesNotDecodeOrEmitAsBso()
{
    constexpr std::uint32_t kBranchIfFalse = 4;
    constexpr std::uint32_t kCr2SummaryOverflowBit = 11;
    const auto encoded = Encode(EncodeConditionBranch(kBranchIfFalse, kCr2SummaryOverflowBit, 8));
    ppc_insn instruction{};
    const auto emitted = Emit(encoded, Function{kFunctionBase, 12}, instruction);

    return instruction.opcode != nullptr && instruction.opcode->id == PPC_INST_BNS &&
           emitted.empty();
}

bool TestFatalGapResultIncludesUnreachableSwitchCases()
{
    Recompiler recompiler;
    if (recompiler.HasFatalGaps())
    {
        std::cerr << "clean recompilation was classified as fatal\n";
        return false;
    }

    recompiler.unreachableSwitchCaseCount = 1;
    if (!recompiler.HasFatalGaps())
    {
        std::cerr << "unreachable switch case was not classified as fatal\n";
        return false;
    }

    recompiler.unreachableSwitchCaseCount = 0;
    recompiler.unrecognizedInstructionCount = 1;
    if (!recompiler.HasFatalGaps())
    {
        std::cerr << "unrecognized instruction was not classified as fatal\n";
        return false;
    }

    return true;
}

bool TestInlineSwitchOwnsDisjointCasesAndSkipsTableData()
{
    constexpr std::uint32_t kTable = kSwitchBase + 8;
    constexpr std::uint32_t kCase0 = kTable + 0x10;
    constexpr std::uint32_t kUnrelated = kCase0 + 0x10;
    constexpr std::uint32_t kSharedEpilogue = kSwitchBase + 0x40;

    auto recompiler = MakeInlineSwitchFixture();
    recompiler.ResolveSwitchFunctionOwnership();
    if (recompiler.functions.size() != 2 || recompiler.functions[0].base != kSwitchBase ||
        recompiler.functions[1].base != kUnrelated)
    {
        std::cerr << "switch cases or shared epilogue remained fake functions\n";
        return false;
    }

    const auto &owner = recompiler.functions[0];
    if (!owner.ContainsAddress(kCase0) || !owner.ContainsAddress(kSharedEpilogue) ||
        owner.ContainsAddress(kTable) || owner.ContainsAddress(kUnrelated))
    {
        std::cerr << "disjoint switch ownership included data or unrelated code\n";
        return false;
    }

    recompiler.out.clear();
    const auto allRecognized = recompiler.Recompile(owner);
    return allRecognized && recompiler.unreachableSwitchCaseCount == 0 &&
           Contains(recompiler.out, "case 0:\n\t\tgoto loc_2018;") &&
           Contains(recompiler.out, "case 3:\n\t\tgoto loc_2024;") &&
           Contains(recompiler.out, "goto loc_2040;") && Contains(recompiler.out, "loc_2040:") &&
           Omits(recompiler.out, "ctx.r3.s64 = ctx.r3.s64 + 1;");
}

bool TestSwitchLabelsSeedMissingCodeFragments()
{
    constexpr std::uint32_t kTable = kSwitchBase + 8;
    constexpr std::uint32_t kCase0 = kTable + 0x10;
    constexpr std::uint32_t kUnrelated = kCase0 + 0x10;
    constexpr std::uint32_t kSharedEpilogue = kSwitchBase + 0x40;

    auto recompiler = MakeInlineSwitchFixture(false);
    recompiler.ResolveSwitchFunctionOwnership();
    if (recompiler.functions.size() != 2 || recompiler.functions[0].base != kSwitchBase ||
        recompiler.functions[1].base != kUnrelated)
    {
        std::cerr << "switch-aware discovery retained or created fake case functions\n";
        return false;
    }

    const auto &owner = recompiler.functions.front();
    return owner.ContainsAddress(kCase0) && owner.ContainsAddress(kSharedEpilogue) &&
           !owner.ContainsAddress(kTable) && !owner.ContainsAddress(kUnrelated);
}

bool TestInvalidSwitchOwnershipIsRefused()
{
    constexpr std::uint32_t kTable = kSwitchBase + 8;
    constexpr std::uint32_t kCase0 = kTable + 0x10;
    constexpr std::uint32_t kUnrelated = kCase0 + 0x10;

    auto dataTarget = MakeInlineSwitchFixture();
    dataTarget.config.switchTables.at(kSwitchBase).labels = {kTable};
    if (!RefusesSwitchLayout(std::move(dataTarget), "reaches data"))
    {
        return false;
    }

    auto outsideTarget = MakeInlineSwitchFixture();
    outsideTarget.config.switchTables.at(kSwitchBase).labels = {kSwitchBase + 0x200};
    if (!RefusesSwitchLayout(std::move(outsideTarget), "outside executable code"))
    {
        return false;
    }

    auto foreignTarget = MakeInlineSwitchFixture();
    foreignTarget.config.switchTables.at(kSwitchBase).labels = {kUnrelated};
    if (!RefusesSwitchLayout(std::move(foreignTarget), "targets foreign function"))
    {
        return false;
    }

    auto overlappingTarget = MakeInlineSwitchFixture();
    AddFunction(overlappingTarget, kCase0, 4);
    return RefusesSwitchLayout(std::move(overlappingTarget), "2 code owners");
}

Recompiler MakeNestedSwitchFixture(const bool reverseInsertion)
{
    constexpr std::uint32_t kOuter = 0x3000;
    constexpr std::uint32_t kOuterTable = kOuter + 8;
    constexpr std::uint32_t kInner = kOuterTable + 0x10;
    constexpr std::uint32_t kInnerTable = kInner + 8;
    constexpr std::uint32_t kCase0 = kInnerTable + 0x10;
    constexpr std::uint32_t kCase1 = kCase0 + 4;

    Recompiler recompiler;
    recompiler.image.base = kOuter;
    recompiler.image.size = kSyntheticCodeSize;
    recompiler.image.data = std::make_unique<std::uint8_t[]>(kSyntheticCodeSize);
    recompiler.image.Map(".text", 0, kSyntheticCodeSize, SectionFlags_Code,
                         recompiler.image.data.get());
    SetWord(recompiler, kOuter, 0x7C0903A6);
    SetWord(recompiler, kOuter + 4, 0x4E800420);
    SetWord(recompiler, kInner, 0x7C0903A6);
    SetWord(recompiler, kInner + 4, 0x4E800420);
    SetWord(recompiler, kCase0, 0x4E800020);
    SetWord(recompiler, kCase1, 0x4E800020);

    recompiler.config.dataRanges = {{kOuterTable, 0x10}, {kInnerTable, 0x10}};
    const RecompilerSwitchTable outerTable{3, {kInner}};
    const RecompilerSwitchTable innerTable{4, {kCase0, kCase1}};
    if (reverseInsertion)
    {
        recompiler.config.switchTables.emplace(kInner, innerTable);
        recompiler.config.switchTables.emplace(kOuter, outerTable);
    }
    else
    {
        recompiler.config.switchTables.emplace(kOuter, outerTable);
        recompiler.config.switchTables.emplace(kInner, innerTable);
    }

    AddFunction(recompiler, kOuter, 8, true);
    AddFunction(recompiler, kInner, 8);
    AddFunction(recompiler, kCase0, 4);
    AddFunction(recompiler, kCase1, 4);
    return recompiler;
}

bool TestNestedSwitchOwnershipIsOrderIndependent()
{
    auto forward = MakeNestedSwitchFixture(false);
    auto reverse = MakeNestedSwitchFixture(true);
    forward.ResolveSwitchFunctionOwnership();
    reverse.ResolveSwitchFunctionOwnership();
    if (forward.functions.size() != 1 || reverse.functions.size() != 1)
    {
        std::cerr << "nested switch fragments retained fake owners\n";
        return false;
    }
    const auto forwardBlocks = forward.functions.front().ExecutableBlocks();
    const auto reverseBlocks = reverse.functions.front().ExecutableBlocks();
    if (forwardBlocks.size() != reverseBlocks.size())
    {
        std::cerr << "switch-table insertion order changed block ownership\n";
        return false;
    }
    for (std::size_t index = 0; index < forwardBlocks.size(); ++index)
    {
        if (forwardBlocks[index].base != reverseBlocks[index].base ||
            forwardBlocks[index].size != reverseBlocks[index].size)
        {
            std::cerr << "switch-table insertion order changed executable blocks\n";
            return false;
        }
    }
    return true;
}

bool TestOverlappingAnalysisBlocksEmitEachInstructionOnce()
{
    constexpr std::uint32_t kBase = 0x4000;
    Recompiler recompiler;
    recompiler.image.base = kBase;
    recompiler.image.size = 16;
    recompiler.image.data = std::make_unique<std::uint8_t[]>(16);
    recompiler.image.Map(".text", 0, 16, SectionFlags_Code, recompiler.image.data.get());

    SetWord(recompiler, kBase, EncodeBranch(kBase, kBase + 8));
    SetWord(recompiler, kBase + 4, 0x4E800020);
    SetWord(recompiler, kBase + 8, 0x38630001);
    SetWord(recompiler, kBase + 12, 0x4E800020);

    Function function{kBase, 16};
    function.blocks = {{0, 16}, {8, 8}};
    recompiler.image.symbols.emplace("sub_4000", kBase, 16, Symbol_Function);

    if (!recompiler.Recompile(function))
    {
        std::cerr << "overlapping analysis blocks failed to recompile\n";
        return false;
    }
    const std::string_view emitted = recompiler.out;
    const auto first = emitted.find("loc_4008:");
    return first != std::string_view::npos &&
           emitted.find("loc_4008:", first + 1) == std::string_view::npos;
}
} // namespace

int main()
{
    if (!TestLhbrxDecoderAndEmission() || !TestLhzxDoesNotDecodeOrEmitAsLhbrx() ||
        !TestBsoDecoderAndEmission() || !TestBnsDoesNotDecodeOrEmitAsBso() ||
        !TestFatalGapResultIncludesUnreachableSwitchCases() ||
        !TestInlineSwitchOwnsDisjointCasesAndSkipsTableData() ||
        !TestSwitchLabelsSeedMissingCodeFragments() || !TestInvalidSwitchOwnershipIsRefused() ||
        !TestNestedSwitchOwnershipIsOrderIndependent() ||
        !TestOverlappingAnalysisBlocksEmitEachInstructionOnce())
    {
        return 1;
    }
    return 0;
}
