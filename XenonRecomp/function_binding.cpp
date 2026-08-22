#include "function_binding.h"

FunctionBindingText EmitFunctionBinding(const std::string_view functionName)
{
    const std::string name(functionName);
    const std::string implementationName = "__imp__" + name;
    const std::string overrideMacro = "PPC_RECOMP_OVERRIDE_" + name;

    FunctionBindingText binding;
    binding.declaration =
        "#if defined(PPC_RECOMP_DIRECT_UNBOUND) && !defined(" + overrideMacro + ")\n";
    binding.declaration +=
        "__attribute__((alias(\"" + implementationName + "\"))) PPC_FUNC(" + name + ");\n#endif\n";

    binding.implementationOpen = "PPC_FUNC_IMPL(" + implementationName + ") {\n";

    binding.forwarder =
        "#if !defined(PPC_RECOMP_DIRECT_UNBOUND) || defined(" + overrideMacro + ")\n";
    binding.forwarder +=
        "PPC_WEAK_FUNC(" + name + ") {\n\t" + implementationName + "(ctx, base);\n}\n#endif\n\n";
    return binding;
}

std::string EmitRecompilationUnitPreamble()
{
    return "#include \"ppc_recomp_shared.h\"\n\n"
           "#ifdef PPC_RECOMP_BINDINGS_HEADER\n"
           "#include PPC_RECOMP_BINDINGS_HEADER\n"
           "#endif\n\n";
}
