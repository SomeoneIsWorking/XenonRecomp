#pragma once

#include <string>
#include <string_view>

struct FunctionBindingText
{
    std::string declaration;
    std::string implementationOpen;
    std::string forwarder;
};

FunctionBindingText EmitFunctionBinding(std::string_view functionName);
std::string EmitRecompilationUnitPreamble();
