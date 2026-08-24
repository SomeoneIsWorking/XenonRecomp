#pragma once
#include <memory>
#include <string>
#include <vector>
#include <set>
#include <section.h>
#include "symbol_table.h"

/**
 * \brief An imported *variable* rather than an imported function.
 *
 * The loader cannot synthesise a stub for these the way it can for functions:
 * the thunk slot has to end up holding the address of the real variable, which
 * only the runtime can decide. Recording them here lets the runtime resolve
 * them instead of leaving the game to dereference an unresolved ordinal record.
 */
struct ImportVariable
{
    std::string name{};    // "__imp__XexExecutableModuleHandle", or empty if the ordinal is unknown
    std::string library{}; // "xboxkrnl.exe", "xam.xex", ...
    uint32_t thunkAddress{};
    uint32_t ordinal{};
};

enum class ImportKind
{
    Variable,
    Function,
};

struct ImportSymbol
{
    std::string name{};
    std::string library{};
    uint32_t thunkAddress{};
    uint32_t recordAddress{};
    uint32_t ordinal{};
    ImportKind kind{};
};

struct Image
{
    std::unique_ptr<uint8_t[]> data{};
    size_t base{};
    uint32_t size{};
    uint32_t capacity{};

    size_t entry_point{};
    std::set<Section, SectionComparer> sections{};
    SymbolTable symbols{};
    std::vector<ImportSymbol> imports{};
    std::vector<ImportVariable> importVariables{};

    /**
     * \brief Map data to image by RVA
     * \param name Name of section
     * \param base Section RVA
     * \param size Section Size
     * \param flags Section Flags, enum SectionFlags
     * \param data Section data
     */
    void Map(const std::string_view &name, size_t base, uint32_t size, uint8_t flags,
             uint8_t *data);

    /**
     * \param address Virtual Address
     * \return Pointer to image owned data
     */
    const void *Find(size_t address) const;

    /**
     * \brief Resolve a complete guest range inside one mapped section.
     * \return Pointer to image-owned data, or nullptr when any byte is unmapped.
     */
    void *FindRange(size_t address, size_t length);
    const void *FindRange(size_t address, size_t length) const;

    /**
     * \param name Name of section
     * \return Section
     */
    const Section *Find(const std::string_view &name) const;

    /**
     * \brief Parse given data to an image, reallocates with ownership
     * \param data Pointer to data
     * \param size Size of data
     * \return Parsed image
     */
    static Image ParseImage(const uint8_t *data, size_t size);
};

Image ElfLoadImage(const uint8_t *data, size_t size);
