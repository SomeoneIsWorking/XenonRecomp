#include "pch.h"
#include "recompiler.h"

#include "data_range.h"
#include "function_binding.h"
#include "function_scan.h"

#include <byteswap.h>
#include <disasm.h>
#include <stdexcept>

namespace
{
const Section *FindCodeSection(const Image &image, size_t address)
{
    const auto section = std::find_if(image.sections.begin(), image.sections.end(),
                                      [address](const Section &candidate)
                                      {
                                          return (candidate.flags & SectionFlags_Code) != 0 &&
                                                 address >= candidate.base &&
                                                 address - candidate.base < candidate.size;
                                      });
    return section == image.sections.end() ? nullptr : &*section;
}

std::vector<size_t> FindOwners(const std::vector<Function> &functions,
                               const std::vector<bool> &absorbed, size_t address)
{
    std::vector<size_t> owners;
    for (size_t index = 0; index < functions.size(); ++index)
    {
        if (!absorbed[index] && functions[index].ContainsAddress(address))
        {
            owners.push_back(index);
        }
    }
    return owners;
}

void RemoveFunctionSymbol(SymbolTable &symbols, size_t address)
{
    for (auto symbol = symbols.begin(); symbol != symbols.end(); ++symbol)
    {
        if (symbol->address == address && symbol->type == Symbol_Function)
        {
            symbols.erase(symbol);
            return;
        }
    }
}

void WidenFunctionSymbol(SymbolTable &symbols, const Function &function)
{
    for (auto symbol = symbols.begin(); symbol != symbols.end(); ++symbol)
    {
        if (symbol->address == function.base && symbol->type == Symbol_Function)
        {
            Symbol widened = *symbol;
            widened.size = function.size;
            symbols.erase(symbol);
            symbols.emplace(std::move(widened));
            return;
        }
    }
}

std::vector<size_t> DirectBranchTargets(const Image &image, const Function &function)
{
    std::vector<size_t> targets;
    for (const auto &block : function.ExecutableBlocks())
    {
        const auto blockBase = function.base + block.base;
        const auto *data = static_cast<const uint32_t *>(image.Find(blockBase));
        for (size_t offset = 0; offset < block.size; offset += sizeof(uint32_t))
        {
            const auto address = blockBase + offset;
            const auto instruction = ByteSwap(data[offset / sizeof(uint32_t)]);
            if (PPC_BL(instruction))
            {
                continue;
            }
            if (PPC_OP(instruction) == PPC_OP_B)
            {
                targets.push_back(address + PPC_BI(instruction));
            }
            else if (PPC_OP(instruction) == PPC_OP_BC)
            {
                targets.push_back(address + PPC_BD(instruction));
            }
        }
    }
    return targets;
}
} // namespace

void Recompiler::Analyse()
{
    for (size_t i = 14; i < 128; i++)
    {
        if (i < 32)
        {
            if (config.restGpr14Address != 0)
            {
                auto &restgpr = functions.emplace_back();
                restgpr.base = config.restGpr14Address + (i - 14) * 4;
                restgpr.size = (32 - i) * 4 + 12;
                image.symbols.emplace(Symbol{fmt::format("__restgprlr_{}", i), restgpr.base,
                                             restgpr.size, Symbol_Function});
            }

            if (config.saveGpr14Address != 0)
            {
                auto &savegpr = functions.emplace_back();
                savegpr.base = config.saveGpr14Address + (i - 14) * 4;
                savegpr.size = (32 - i) * 4 + 8;
                image.symbols.emplace(fmt::format("__savegprlr_{}", i), savegpr.base, savegpr.size,
                                      Symbol_Function);
            }

            if (config.restFpr14Address != 0)
            {
                auto &restfpr = functions.emplace_back();
                restfpr.base = config.restFpr14Address + (i - 14) * 4;
                restfpr.size = (32 - i) * 4 + 4;
                image.symbols.emplace(fmt::format("__restfpr_{}", i), restfpr.base, restfpr.size,
                                      Symbol_Function);
            }

            if (config.saveFpr14Address != 0)
            {
                auto &savefpr = functions.emplace_back();
                savefpr.base = config.saveFpr14Address + (i - 14) * 4;
                savefpr.size = (32 - i) * 4 + 4;
                image.symbols.emplace(fmt::format("__savefpr_{}", i), savefpr.base, savefpr.size,
                                      Symbol_Function);
            }

            if (config.restVmx14Address != 0)
            {
                auto &restvmx = functions.emplace_back();
                restvmx.base = config.restVmx14Address + (i - 14) * 8;
                restvmx.size = (32 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__restvmx_{}", i), restvmx.base, restvmx.size,
                                      Symbol_Function);
            }

            if (config.saveVmx14Address != 0)
            {
                auto &savevmx = functions.emplace_back();
                savevmx.base = config.saveVmx14Address + (i - 14) * 8;
                savevmx.size = (32 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__savevmx_{}", i), savevmx.base, savevmx.size,
                                      Symbol_Function);
            }
        }

        if (i >= 64)
        {
            if (config.restVmx64Address != 0)
            {
                auto &restvmx = functions.emplace_back();
                restvmx.base = config.restVmx64Address + (i - 64) * 8;
                restvmx.size = (128 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__restvmx_{}", i), restvmx.base, restvmx.size,
                                      Symbol_Function);
            }

            if (config.saveVmx64Address != 0)
            {
                auto &savevmx = functions.emplace_back();
                savevmx.base = config.saveVmx64Address + (i - 64) * 8;
                savevmx.size = (128 - i) * 8 + 4;
                image.symbols.emplace(fmt::format("__savevmx_{}", i), savevmx.base, savevmx.size,
                                      Symbol_Function);
            }
        }
    }

    for (auto &[address, size] : config.functions)
    {
        functions.emplace_back(address, size);
        image.symbols.emplace(fmt::format("sub_{:X}", address), address, size, Symbol_Function);
    }

    auto &pdata = *image.Find(".pdata");
    size_t count = pdata.size / sizeof(IMAGE_CE_RUNTIME_FUNCTION);
    auto *pf = (IMAGE_CE_RUNTIME_FUNCTION *)pdata.data;
    for (size_t i = 0; i < count; i++)
    {
        auto fn = pf[i];
        fn.BeginAddress = ByteSwap(fn.BeginAddress);
        fn.Data = ByteSwap(fn.Data);

        if (image.symbols.find(fn.BeginAddress) == image.symbols.end())
        {
            auto &f = functions.emplace_back();
            f.base = fn.BeginAddress;
            f.size = fn.FunctionLength * 4;

            image.symbols.emplace(fmt::format("sub_{:X}", f.base), f.base, f.size, Symbol_Function);
        }
    }

    authoritativeFunctionStarts.clear();
    for (const auto &function : functions)
    {
        authoritativeFunctionStarts.emplace(function.base);
    }

    ValidateDataRanges(config.dataRanges, image);

    for (const auto &section : image.sections)
    {
        if (!(section.flags & SectionFlags_Code))
        {
            continue;
        }
        for (const auto address : DiscoverBranchAndLinkTargets(section.data, section.base,
                                                               section.size, config.dataRanges))
        {
            if (address >= section.base && address < section.base + section.size &&
                image.symbols.find(address) == image.symbols.end())
            {
                auto *targetData = section.data + address - section.base;
                auto &fn = functions.emplace_back(
                    AnalyzeFunctionGap(targetData, address, section.base + section.size,
                                       image.symbols, config.dataRanges));
                authoritativeFunctionStarts.emplace(fn.base);
                image.symbols.emplace(fmt::format("sub_{:X}", fn.base), fn.base, fn.size,
                                      Symbol_Function);
            }
        }

        size_t base = section.base;
        uint8_t *data = section.data;
        uint8_t *dataEnd = section.data + section.size;

        while (data < dataEnd)
        {
            if (const auto skip = DataRangeScanSkip(config.dataRanges, base))
            {
                base += skip;
                data += skip;
                continue;
            }
            auto invalidInstr = config.invalidInstructions.find(ByteSwap(*(uint32_t *)data));
            if (invalidInstr != config.invalidInstructions.end())
            {
                base += invalidInstr->second;
                data += invalidInstr->second;
                continue;
            }

            auto fnSymbol = image.symbols.find(base);
            if (fnSymbol != image.symbols.end() && fnSymbol->address == base &&
                fnSymbol->type == Symbol_Function)
            {
                assert(fnSymbol->address == base);

                base += fnSymbol->size;
                data += fnSymbol->size;
            }
            else
            {
                auto &fn = functions.emplace_back(AnalyzeFunctionGap(
                    data, base, section.base + section.size, image.symbols, config.dataRanges));
                image.symbols.emplace(fmt::format("sub_{:X}", fn.base), fn.base, fn.size,
                                      Symbol_Function);

                base += fn.size;
                data += fn.size;
            }
        }
    }

    std::sort(functions.begin(), functions.end(),
              [](auto &lhs, auto &rhs) { return lhs.base < rhs.base; });

    ResolveSwitchFunctionOwnership();
}

void Recompiler::ResolveSwitchFunctionOwnership()
{
    std::vector<bool> absorbed(functions.size(), false);
    std::unordered_set<size_t> widenedOwners;

    std::vector<size_t> switchSites;
    switchSites.reserve(config.switchTables.size());
    for (const auto &[address, table] : config.switchTables)
    {
        (void)table;
        switchSites.push_back(address);
    }
    std::sort(switchSites.begin(), switchSites.end());

    const auto adoptCodeAt = [&](size_t ownerIndex, size_t address, size_t switchSite,
                                 bool switchLabel, auto &&adoptCodeAtRef) -> void
    {
        if (DataRangeContaining(config.dataRanges, address) != nullptr)
        {
            throw std::runtime_error(
                fmt::format("switch at 0x{:X} reaches data at 0x{:X}", switchSite, address));
        }
        if (FindCodeSection(image, address) == nullptr)
        {
            throw std::runtime_error(fmt::format(
                "switch at 0x{:X} reaches outside executable code at 0x{:X}", switchSite, address));
        }

        auto owners = FindOwners(functions, absorbed, address);
        if (owners.empty())
        {
            for (size_t index = 0; index < functions.size(); ++index)
            {
                const auto &candidate = functions[index];
                const bool isAuthoritative = authoritativeFunctionStarts.find(candidate.base) !=
                                             authoritativeFunctionStarts.end();
                const bool isInEnvelope =
                    address >= candidate.base && address - candidate.base < candidate.size;
                if (!absorbed[index] && index != ownerIndex && isAuthoritative && isInEnvelope)
                {
                    throw std::runtime_error(
                        fmt::format("switch at 0x{:X} targets foreign function 0x{:X}", switchSite,
                                    candidate.base));
                }
            }

            const auto *section = FindCodeSection(image, address);
            const auto fragment =
                AnalyzeFunctionGap(section->data + address - section->base, address,
                                   section->base + section->size, image.symbols, config.dataRanges);
            const auto branchTargets = DirectBranchTargets(image, fragment);
            functions[ownerIndex].AbsorbCode(fragment);
            widenedOwners.emplace(ownerIndex);

            for (const auto branchTarget : branchTargets)
            {
                if (!functions[ownerIndex].ContainsAddress(branchTarget) &&
                    FindCodeSection(image, branchTarget) != nullptr)
                {
                    adoptCodeAtRef(ownerIndex, branchTarget, switchSite, false, adoptCodeAtRef);
                }
            }
            return;
        }
        if (owners.size() != 1)
        {
            throw std::runtime_error(
                fmt::format("switch at 0x{:X} has {} code owners for target 0x{:X}", switchSite,
                            owners.size(), address));
        }

        const auto targetIndex = owners.front();
        if (targetIndex == ownerIndex)
        {
            return;
        }
        if (authoritativeFunctionStarts.find(functions[targetIndex].base) !=
            authoritativeFunctionStarts.end())
        {
            if (switchLabel)
            {
                throw std::runtime_error(
                    fmt::format("switch at 0x{:X} targets foreign function 0x{:X}", switchSite,
                                functions[targetIndex].base));
            }
            return;
        }

        const auto branchTargets = DirectBranchTargets(image, functions[targetIndex]);
        functions[ownerIndex].AbsorbCode(functions[targetIndex]);
        absorbed[targetIndex] = true;
        widenedOwners.emplace(ownerIndex);

        for (const auto branchTarget : branchTargets)
        {
            if (functions[ownerIndex].ContainsAddress(branchTarget))
            {
                continue;
            }
            if (FindCodeSection(image, branchTarget) == nullptr)
            {
                continue;
            }
            adoptCodeAtRef(ownerIndex, branchTarget, switchSite, false, adoptCodeAtRef);
        }
    };

    for (const auto switchSite : switchSites)
    {
        const auto owners = FindOwners(functions, absorbed, switchSite);
        if (owners.size() != 1)
        {
            throw std::runtime_error(fmt::format("switch sequence at 0x{:X} has {} code owners",
                                                 switchSite, owners.size()));
        }
        const auto ownerIndex = owners.front();
        for (const auto label : config.switchTables.at(static_cast<uint32_t>(switchSite)).labels)
        {
            adoptCodeAt(ownerIndex, label, switchSite, true, adoptCodeAt);
        }
    }

    for (const auto ownerIndex : widenedOwners)
    {
        if (!absorbed[ownerIndex])
        {
            WidenFunctionSymbol(image.symbols, functions[ownerIndex]);
            ++extendedSwitchFunctionCount;
        }
    }

    std::vector<Function> kept;
    kept.reserve(functions.size());
    for (size_t index = 0; index < functions.size(); ++index)
    {
        if (absorbed[index])
        {
            RemoveFunctionSymbol(image.symbols, functions[index].base);
            continue;
        }
        kept.push_back(std::move(functions[index]));
    }
    functions = std::move(kept);
}

bool Recompiler::Recompile(const Function &fn)
{
    const auto codeBlocks = fn.ExecutableBlocks();

    static std::unordered_set<size_t> labels;
    labels.clear();

    for (const auto &block : codeBlocks)
    {
        const auto blockBase = fn.base + block.base;
        const auto *blockData = static_cast<const uint32_t *>(image.Find(blockBase));
        for (size_t offset = 0; offset < block.size; offset += sizeof(uint32_t))
        {
            const auto addr = blockBase + offset;
            const uint32_t instruction = ByteSwap(blockData[offset / sizeof(uint32_t)]);
            if (!PPC_BL(instruction))
            {
                const size_t op = PPC_OP(instruction);
                if (op == PPC_OP_B && fn.ContainsAddress(addr + PPC_BI(instruction)))
                    labels.emplace(addr + PPC_BI(instruction));
                else if (op == PPC_OP_BC && fn.ContainsAddress(addr + PPC_BD(instruction)))
                    labels.emplace(addr + PPC_BD(instruction));
            }

            auto switchTable = config.switchTables.find(addr);
            if (switchTable != config.switchTables.end())
            {
                for (auto label : switchTable->second.labels)
                {
                    if (fn.ContainsAddress(label))
                        labels.emplace(label);
                }
            }

            auto midAsmHook = config.midAsmHooks.find(addr);
            if (midAsmHook != config.midAsmHooks.end())
            {
                if (midAsmHook->second.returnOnFalse || midAsmHook->second.returnOnTrue ||
                    midAsmHook->second.jumpAddressOnFalse != NULL ||
                    midAsmHook->second.jumpAddressOnTrue != NULL)
                {
                    print("extern bool ");
                }
                else
                {
                    print("extern void ");
                }

                print("{}(", midAsmHook->second.name);
                for (auto &reg : midAsmHook->second.registers)
                {
                    if (out.back() != '(')
                        out += ", ";

                    switch (reg[0])
                    {
                    case 'c':
                        if (reg == "ctr")
                            print("PPCRegister& ctr");
                        else
                            print("PPCCRRegister& {}", reg);
                        break;

                    case 'x':
                        print("PPCXERRegister& xer");
                        break;

                    case 'r':
                        print("PPCRegister& {}", reg);
                        break;

                    case 'f':
                        if (reg == "fpscr")
                            print("PPCFPSCRRegister& fpscr");
                        else
                            print("PPCRegister& {}", reg);
                        break;

                    case 'v':
                        print("PPCVRegister& {}", reg);
                        break;
                    }
                }

                println(");\n");

                if (midAsmHook->second.jumpAddress != NULL)
                    labels.emplace(midAsmHook->second.jumpAddress);
                if (midAsmHook->second.jumpAddressOnTrue != NULL)
                    labels.emplace(midAsmHook->second.jumpAddressOnTrue);
                if (midAsmHook->second.jumpAddressOnFalse != NULL)
                    labels.emplace(midAsmHook->second.jumpAddressOnFalse);
            }
        }
    }

    auto symbol = image.symbols.find(fn.base);
    std::string name;
    if (symbol != image.symbols.end())
    {
        name = symbol->name;
    }
    else
    {
        name = fmt::format("sub_{}", fn.base);
    }

    const auto binding = EmitFunctionBinding(name);
    out.append(binding.declaration).append(binding.implementationOpen);
    println("\tPPC_FUNC_PROLOGUE();");

    auto switchTable = config.switchTables.end();
    bool allRecompiled = true;
    CSRState csrState = CSRState::Unknown;

    // TODO: the printing scheme here is scuffed
    RecompilerLocalVariables localVariables;
    static std::string tempString;
    tempString.clear();
    std::swap(out, tempString);

    ppc_insn insn{};
    for (const auto &block : codeBlocks)
    {
        auto base = fn.base + block.base;
        const auto end = base + block.size;
        auto *data = (uint32_t *)image.Find(base);
        csrState = CSRState::Unknown;
        while (base < end)
        {
            if (labels.find(base) != labels.end())
            {
                println("loc_{:X}:", base);

                // Anyone could jump to this label so we wouldn't know what the CSR state would be.
                csrState = CSRState::Unknown;
            }

            if (switchTable == config.switchTables.end())
                switchTable = config.switchTables.find(base);

            ppc::Disassemble(data, 4, base, insn);

            if (insn.opcode == nullptr)
            {
                println("\t// {}", insn.op_str);
#if 1
                if (*data != 0)
                    fmt::println("Unable to decode instruction {:X} at {:X}", *data, base);
#endif
            }
            else
            {
                if (insn.opcode->id == PPC_INST_BCTR &&
                    (*(data - 1) == 0x07008038 || *(data - 1) == 0x00000060) &&
                    switchTable == config.switchTables.end())
                    fmt::println(
                        "Found a switch jump table at {:X} with no switch table entry present",
                        base);

                if (!Recompile(fn, base, insn, data, switchTable, localVariables, csrState))
                {
                    fmt::println("Unrecognized instruction at 0x{:X}: {}", base, insn.opcode->name);
                    // Emitting nothing here would let the following instructions run
                    // against stale registers and silently produce wrong results, so
                    // trap instead and make the gap fail loudly at runtime.
                    println("\t__builtin_debugtrap(); // unrecognized instruction: {}",
                            insn.opcode->name);
                    ++unrecognizedInstructionCount;
                    allRecompiled = false;
                }
            }

            base += 4;
            ++data;
        }
    }

#if 0
    if (insn.opcode == nullptr || (insn.opcode->id != PPC_INST_B && insn.opcode->id != PPC_INST_BCTR && insn.opcode->id != PPC_INST_BLR))
        fmt::println("Function at {:X} ends prematurely with instruction {} at {:X}", fn.base, insn.opcode != nullptr ? insn.opcode->name : "INVALID", base - 4);
#endif

    println("}}\n");

    out += binding.forwarder;

    std::swap(out, tempString);
    if (localVariables.ctr)
        println("\tPPCRegister ctr{{}};");
    if (localVariables.xer)
        println("\tPPCXERRegister xer{{}};");
    if (localVariables.reserved)
        println("\tPPCRegister reserved{{}};");

    for (size_t i = 0; i < 8; i++)
    {
        if (localVariables.cr[i])
            println("\tPPCCRRegister cr{}{{}};", i);
    }

    for (size_t i = 0; i < 32; i++)
    {
        if (localVariables.r[i])
            println("\tPPCRegister r{}{{}};", i);
    }

    for (size_t i = 0; i < 32; i++)
    {
        if (localVariables.f[i])
            println("\tPPCRegister f{}{{}};", i);
    }

    for (size_t i = 0; i < 128; i++)
    {
        if (localVariables.v[i])
            println("\tPPCVRegister v{}{{}};", i);
    }

    if (localVariables.env)
        println("\tPPCContext env{{}};");

    if (localVariables.temp)
        println("\tPPCRegister temp{{}};");

    if (localVariables.vTemp)
        println("\tPPCVRegister vTemp{{}};");

    if (localVariables.ea)
        println("\tuint32_t ea{{}};");

    out += tempString;

    return allRecompiled;
}
