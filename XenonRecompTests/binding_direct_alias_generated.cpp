#include "binding_link_fixture.h"

#define PPC_RECOMP_DIRECT_UNBOUND

#if defined(PPC_RECOMP_DIRECT_UNBOUND) && !defined(PPC_RECOMP_OVERRIDE_binding_test_direct_target)
__attribute__((alias("__imp__binding_test_direct_target"))) PPC_FUNC(binding_test_direct_target);
#endif

PPC_FUNC_IMPL(__imp__binding_test_direct_target)
{
    ctx.value += 2;
}

#if !defined(PPC_RECOMP_DIRECT_UNBOUND) || defined(PPC_RECOMP_OVERRIDE_binding_test_direct_target)
PPC_WEAK_FUNC(binding_test_direct_target)
{
    __imp__binding_test_direct_target(ctx, base);
}
#endif

void BindingTestDirectCaller(BindingTestContext &ctx, std::uint8_t *base)
{
    binding_test_direct_target(ctx, base);
}

std::uintptr_t BindingTestDirectTargetAddress()
{
    return reinterpret_cast<std::uintptr_t>(&binding_test_direct_target);
}

std::uintptr_t BindingTestDirectImplementationAddress()
{
    return reinterpret_cast<std::uintptr_t>(&__imp__binding_test_direct_target);
}
