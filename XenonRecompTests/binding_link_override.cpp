#include "binding_link_fixture.h"

PPC_FUNC(binding_test_target)
{
    ctx.value += 10;
    __imp__binding_test_target(ctx, base);
}
