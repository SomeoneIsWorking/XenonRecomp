#include "function.h"
#include <disasm.h>
#include <vector>
#include <bit>
#include <algorithm>
#include <cassert>
#include <byteswap.h>
#include <stdexcept>

size_t Function::SearchBlock(size_t address) const
{
    if (address < base)
    {
        return -1;
    }

    for (size_t i = 0; i < blocks.size(); i++)
    {
        const auto &block = blocks[i];
        const auto begin = base + block.base;
        const auto end = begin + block.size;

        if (begin != end)
        {
            if (address >= begin && address < end)
            {
                return i;
            }
        }
        else // fresh block
        {
            if (address == begin)
            {
                return i;
            }
        }
    }

    return -1;
}

bool Function::ContainsAddress(size_t address) const
{
    if (blocks.empty())
    {
        return address >= base && address - base < size;
    }
    return SearchBlock(address) != static_cast<size_t>(-1);
}

std::vector<Function::Block> Function::ExecutableBlocks() const
{
    if (!blocks.empty())
    {
        return blocks;
    }
    if (size == 0)
    {
        return {};
    }
    return {{0, size}};
}

void Function::NormalizeBlocks()
{
    auto normalized = ExecutableBlocks();
    std::sort(normalized.begin(), normalized.end(),
              [](const Block &left, const Block &right) { return left.base < right.base; });

    std::vector<Block> merged;
    merged.reserve(normalized.size());
    for (const auto &block : normalized)
    {
        if (block.size == 0)
        {
            continue;
        }
        if (!merged.empty() && block.base <= merged.back().base + merged.back().size)
        {
            const auto end =
                std::max(merged.back().base + merged.back().size, block.base + block.size);
            merged.back().size = end - merged.back().base;
            merged.back().projectedSize = static_cast<size_t>(-1);
            continue;
        }
        merged.emplace_back(block.base, block.size);
    }
    blocks = std::move(merged);

    size = 0;
    for (const auto &block : blocks)
    {
        size = std::max(size, block.base + block.size);
    }
}

void Function::AbsorbCode(const Function &other)
{
    if (other.base < base)
    {
        throw std::invalid_argument("cannot absorb code before a function entry");
    }

    blocks = ExecutableBlocks();
    const auto offset = other.base - base;
    for (const auto &block : other.ExecutableBlocks())
    {
        blocks.emplace_back(offset + block.base, block.size);
    }
    NormalizeBlocks();
}

Function Function::Analyze(const void *code, size_t size, size_t base)
{
    Function fn{base, 0};

    if (size == 0)
    {
        return fn;
    }

    if (size >= 8 && *((uint32_t *)code + 1) == 0x04000048) // shifted ptr tail call
    {
        fn.size = 0x8;
        return fn;
    }

    auto &blocks = fn.blocks;
    blocks.reserve(8);
    blocks.emplace_back();

    const auto *data = (uint32_t *)code;
    const auto *dataStart = data;
    const auto *dataEnd = (uint32_t *)((uint8_t *)code + size);
    const auto isInRange = [base, size](size_t address)
    { return address >= base && address - base < size; };
    std::vector<size_t> blockStack{};
    blockStack.reserve(32);
    blockStack.emplace_back();

#define RESTORE_DATA()                                                                             \
    if (!blockStack.empty())                                                                       \
        data = (dataStart + ((blocks[blockStack.back()].base + blocks[blockStack.back()].size) /   \
                             sizeof(*data))) -                                                     \
               1; // continue adds one

    // TODO: Branch fallthrough
    for (; data < dataEnd; ++data)
    {
        const size_t addr = base + ((data - dataStart) * sizeof(*data));
        if (blockStack.empty())
        {
            break; // it's hideover
        }

        auto &curBlock = blocks[blockStack.back()];
        DEBUG(const auto blockBase = curBlock.base);
        const uint32_t instruction = ByteSwap(*data);

        const uint32_t op = PPC_OP(instruction);
        const uint32_t xop = PPC_XOP(instruction);
        const uint32_t isLink = PPC_BL(instruction); // call

        ppc_insn insn;
        ppc::Disassemble(data, addr, insn);

        // Sanity check
        assert(addr == base + curBlock.base + curBlock.size);
        if (curBlock.projectedSize != -1 && curBlock.size >= curBlock.projectedSize) // fallthrough
        {
            blockStack.pop_back();
            RESTORE_DATA();
            continue;
        }

        curBlock.size += 4;
        if (op == PPC_OP_BC) // conditional branches all originate from one opcode, thanks RISC
        {
            if (isLink) // just a conditional call, nothing to see here
            {
                continue;
            }

            // TODO: carry projections over to false
            curBlock.projectedSize = -1;
            blockStack.pop_back();

            // TODO: Handle absolute branches?
            assert(!PPC_BA(instruction));
            const size_t branchDest = addr + PPC_BD(instruction);

            // true/false paths
            // left block: false case
            // right block: true case
            const size_t fallthroughAddress = addr + 4;
            const size_t lBase = fallthroughAddress - base;
            const size_t rBase = branchDest - base;

            // these will be -1 if it's our first time seeing these blocks
            auto lBlock = fn.SearchBlock(fallthroughAddress);

            if (isInRange(fallthroughAddress) && lBlock == -1)
            {
                blocks.emplace_back(lBase, 0).projectedSize =
                    isInRange(branchDest) ? rBase - lBase : static_cast<size_t>(-1);
                lBlock = blocks.size() - 1;

                // push this first, this gets overriden by the true case as it'd be further away
                DEBUG(blocks[lBlock].parent = blockBase);
                blockStack.emplace_back(lBlock);
            }

            size_t rBlock = fn.SearchBlock(branchDest);
            if (isInRange(branchDest) && rBlock == -1)
            {
                blocks.emplace_back(branchDest - base, 0);
                rBlock = blocks.size() - 1;

                DEBUG(blocks[rBlock].parent = blockBase);
                blockStack.emplace_back(rBlock);
            }

            RESTORE_DATA();
        }
        else if (op == PPC_OP_B || instruction == 0 ||
                 (op == PPC_OP_CTR && (xop == 16 || xop == 528))) // b, blr, end padding
        {
            if (!isLink)
            {
                blockStack.pop_back();

                if (op == PPC_OP_B)
                {
                    assert(!PPC_BA(instruction));
                    const size_t branchDest = addr + PPC_BI(instruction);

                    const size_t branchBase = branchDest - base;
                    const size_t branchBlock = fn.SearchBlock(branchDest);

                    if (!isInRange(branchDest))
                    {
                        // A branch outside this bounded function is a tail
                        // edge. Do not abandon other local blocks that are
                        // still waiting on the analysis stack.
                        RESTORE_DATA();
                        continue;
                    }

                    // carry over our projection if blocks are next to each other
                    const bool isContinuous = branchBase == curBlock.base + curBlock.size;
                    size_t sizeProjection = (size_t)-1;

                    if (curBlock.projectedSize != -1 && isContinuous)
                    {
                        sizeProjection = curBlock.projectedSize - curBlock.size;
                    }

                    if (branchBlock == -1)
                    {
                        blocks.emplace_back(branchBase, 0, sizeProjection);

                        blockStack.emplace_back(blocks.size() - 1);

                        DEBUG(blocks.back().parent = blockBase);
                        RESTORE_DATA();
                        continue;
                    }
                }
                else if (op == PPC_OP_CTR)
                {
                    // 5th bit of BO tells cpu to ignore the counter, which is a blr/bctr otherwise
                    // it's conditional
                    const bool conditional = !(PPC_BO(instruction) & 0x10);
                    if (conditional)
                    {
                        // right block's just going to return
                        const size_t lBase = (addr - base) + 4;
                        const size_t fallthroughAddress = addr + 4;
                        size_t lBlock = fn.SearchBlock(fallthroughAddress);
                        if (isInRange(fallthroughAddress) && lBlock == -1)
                        {
                            blocks.emplace_back(lBase, 0);
                            lBlock = blocks.size() - 1;

                            DEBUG(blocks[lBlock].parent = blockBase);
                            blockStack.emplace_back(lBlock);
                            RESTORE_DATA();
                            continue;
                        }
                    }
                }

                RESTORE_DATA();
            }
        }
        else if (insn.opcode == nullptr)
        {
            blockStack.pop_back();
            RESTORE_DATA();
        }
    }

    std::sort(blocks.begin(), blocks.end(),
              [](const Block &left, const Block &right) { return left.base < right.base; });
    fn.size = 0;
    for (const auto &block : blocks)
    {
        fn.size = std::max(fn.size, block.base + block.size);
    }
    return fn;
}
