#include "binding_link_fixture.h"

PPC_FUNC_IMPL(__imp__binding_test_target)
{
    ++ctx.value;
}

PPC_WEAK_FUNC(binding_test_target)
{
    __imp__binding_test_target(ctx, base);
}

void BindingTestGeneratedCaller(BindingTestContext &ctx, std::uint8_t *base)
{
    binding_test_target(ctx, base);
}
