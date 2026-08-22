#include "function_binding.h"

FunctionBindingText EmitFunctionBinding(const std::string_view functionName)
{
    const std::string name(functionName);
    return {"PPC_FUNC_IMPL(__imp__" + name + ") {\n",
            "PPC_WEAK_FUNC(" + name + ") {\n\t__imp__" + name + "(ctx, base);\n}\n\n"};
}
