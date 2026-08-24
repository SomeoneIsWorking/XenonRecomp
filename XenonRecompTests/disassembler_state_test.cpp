#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>

#include <disasm.h>

namespace
{
constexpr std::uint64_t kInstructionAddress = 0x82000000;
constexpr std::uint32_t kLoadDoubleword = 0xE8640000;

std::array<std::uint8_t, 4> BigEndianBytes(const std::uint32_t instruction)
{
    return {static_cast<std::uint8_t>(instruction >> 24),
            static_cast<std::uint8_t>(instruction >> 16),
            static_cast<std::uint8_t>(instruction >> 8), static_cast<std::uint8_t>(instruction)};
}

bool DecodeAsLoadDoubleword(ppc::DisassemblerEngine &engine,
                            const std::array<std::uint8_t, 4> &bytes)
{
    ppc_insn instruction{};
    return engine.Disassemble(bytes.data(), bytes.size(), kInstructionAddress, instruction) == 4 &&
           instruction.opcode != nullptr && instruction.opcode->id == PPC_INST_LD;
}

void Require(const bool condition, const char *message)
{
    if (!condition)
    {
        std::cerr << "disassembler state test failed: " << message << '\n';
        std::exit(EXIT_FAILURE);
    }
}
} // namespace

int main()
{
    const auto bytes = BigEndianBytes(kLoadDoubleword);

    ppc::DisassemblerEngine engine64(BFD_ENDIAN_BIG, "cell 64");
    ppc::DisassemblerEngine engine32(BFD_ENDIAN_BIG, "cell 32");

    Require(DecodeAsLoadDoubleword(engine64, bytes),
            "64-bit engine rejected a PPC64-only instruction on first use");
    Require(ppc_disassembler_is_64_bit(&engine64.info),
            "64-bit engine did not retain its configured dialect");
    Require(!DecodeAsLoadDoubleword(engine32, bytes),
            "32-bit engine accepted a PPC64-only instruction on first use");
    Require(!ppc_disassembler_is_64_bit(&engine32.info),
            "32-bit engine retained the 64-bit dialect");
    Require(DecodeAsLoadDoubleword(engine64, bytes),
            "64-bit engine rejected a PPC64-only instruction on cached use");
    Require(ppc_disassembler_is_64_bit(&engine64.info),
            "independent 32-bit engine changed the 64-bit engine dialect");
    Require(!DecodeAsLoadDoubleword(engine32, bytes),
            "32-bit engine accepted a PPC64-only instruction on cached use");
    Require(!ppc_disassembler_is_64_bit(&engine32.info),
            "independent 64-bit engine changed the 32-bit engine dialect");

    std::cout << "disassembler state test passed: independent typed dialects\n";
    return EXIT_SUCCESS;
}
