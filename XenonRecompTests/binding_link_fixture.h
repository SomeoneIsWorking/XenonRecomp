#pragma once

#include <cstdint>

struct BindingTestContext
{
    int value{};
};

#define PPC_FUNC(x) void x(BindingTestContext &ctx, std::uint8_t *base)
#define PPC_FUNC_IMPL(x) extern "C" PPC_FUNC(x)
#define PPC_WEAK_FUNC(x) __attribute__((weak, noinline)) PPC_FUNC(x)

PPC_FUNC(binding_test_target);
PPC_FUNC_IMPL(__imp__binding_test_target);

void BindingTestGeneratedCaller(BindingTestContext &ctx, std::uint8_t *base);
