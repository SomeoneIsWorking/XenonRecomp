#include "binding_link_fixture.h"
#include "function_binding.h"

#include <iostream>
#include <string>

namespace
{
bool ExpectEqual(const std::string_view label, const std::string_view actual,
                 const std::string_view expected)
{
    if (actual == expected)
    {
        return true;
    }

    std::cerr << label << " mismatch\nexpected:\n" << expected << "actual:\n" << actual;
    return false;
}

bool TestBindingEmission()
{
    const auto binding = EmitFunctionBinding("sub_822218C0");
    const std::string emitted =
        binding.declaration + binding.implementationOpen + binding.forwarder;

    return ExpectEqual("selective declaration", binding.declaration,
                       "#if defined(PPC_RECOMP_DIRECT_UNBOUND) && "
                       "!defined(PPC_RECOMP_OVERRIDE_sub_822218C0)\n"
                       "__attribute__((alias(\"__imp__sub_822218C0\"))) "
                       "PPC_FUNC(sub_822218C0);\n"
                       "#endif\n") &&
           ExpectEqual("implementation opening", binding.implementationOpen,
                       "PPC_FUNC_IMPL(__imp__sub_822218C0) {\n") &&
           ExpectEqual("forwarder", binding.forwarder,
                       "#if !defined(PPC_RECOMP_DIRECT_UNBOUND) || "
                       "defined(PPC_RECOMP_OVERRIDE_sub_822218C0)\n"
                       "PPC_WEAK_FUNC(sub_822218C0) {\n"
                       "\t__imp__sub_822218C0(ctx, base);\n"
                       "}\n"
                       "#endif\n\n") &&
           emitted.find("registry") == std::string::npos;
}

bool TestRecompilationUnitPreamble()
{
    return ExpectEqual("recompilation unit preamble", EmitRecompilationUnitPreamble(),
                       "#include \"ppc_recomp_shared.h\"\n\n"
                       "#ifdef PPC_RECOMP_BINDINGS_HEADER\n"
                       "#include PPC_RECOMP_BINDINGS_HEADER\n"
                       "#endif\n\n");
}

bool TestOverrideInterposesSameTranslationUnitCall()
{
    BindingTestContext ctx{};
    BindingTestGeneratedCaller(ctx, nullptr);
    return ctx.value == 11;
}

bool TestRetainedImplementationSupportsSuperCall()
{
    BindingTestContext ctx{};
    __imp__binding_test_target(ctx, nullptr);
    return ctx.value == 1;
}

bool TestDirectBindingHasNoThunk()
{
    BindingTestContext ctx{};
    BindingTestDirectCaller(ctx, nullptr);
    return ctx.value == 2 &&
           BindingTestDirectTargetAddress() == BindingTestDirectImplementationAddress();
}
} // namespace

int main()
{
    if (!TestBindingEmission())
    {
        std::cerr << "binding emission test failed\n";
        return 1;
    }

    if (!TestOverrideInterposesSameTranslationUnitCall())
    {
        std::cerr << "same-translation-unit call bypassed the strong override\n";
        return 1;
    }

    if (!TestRecompilationUnitPreamble())
    {
        std::cerr << "recompilation-unit preamble test failed\n";
        return 1;
    }

    if (!TestRetainedImplementationSupportsSuperCall())
    {
        std::cerr << "retained implementation did not remain directly callable\n";
        return 1;
    }

    if (!TestDirectBindingHasNoThunk())
    {
        std::cerr << "direct binding emitted a forwarding thunk\n";
        return 1;
    }

    return 0;
}
