#include "binding_link_fixture.h"

#define PPC_RECOMP_DIRECT_UNBOUND
#define PPC_RECOMP_OVERRIDE_binding_test_target

#if defined(PPC_RECOMP_DIRECT_UNBOUND) && !defined(PPC_RECOMP_OVERRIDE_binding_test_target)
__attribute__((alias("__imp__binding_test_target"))) PPC_FUNC(binding_test_target);
#endif

PPC_FUNC_IMPL(__imp__binding_test_target)
{
    ++ctx.value;
}

#if !defined(PPC_RECOMP_DIRECT_UNBOUND) || defined(PPC_RECOMP_OVERRIDE_binding_test_target)
PPC_WEAK_FUNC(binding_test_target)
{
    __imp__binding_test_target(ctx, base);
}
#endif

void BindingTestGeneratedCaller(BindingTestContext &ctx, std::uint8_t *base)
{
    binding_test_target(ctx, base);
}
