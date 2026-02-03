
// ============================================
// dotnet_reflection.h - C API for .NET reflection
// ============================================

#ifndef DOTNET_REFLECTION_H
#define DOTNET_REFLECTION_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif
    typedef struct DotNetProcess DotNetProcess;
    typedef struct DotNetClass DotNetClass;
    typedef struct DotNetField DotNetField;

    DotNetProcess *openProcess(uint32_t process_id);
    void *getProcessHandle(DotNetProcess *process);
    void closeProcess(DotNetProcess *process);
    uint32_t findProcess(const char *name);
    DotNetClass *findClass(DotNetProcess *process, const char *class_name);
    const char *classGetName(const DotNetClass *klass);
    const char *classGetNamespace(const DotNetClass *klass);
    const char *classGetFullName(const DotNetClass *klass);
    uint32_t classGetSize(const DotNetClass *klass);
    DotNetField *classFindField(const DotNetClass *klass, const char *field_name);
    const char *fieldGetName(const DotNetField *field);
    uint32_t fieldGetOffset(const DotNetField *field);
    bool fieldIsStatic(const DotNetField *field);
    const char *fieldGetTypeName(const DotNetField *field);
    // bool fieldGetStaticValue(const DotNetField *field, uint64_t *output_ptr);
    bool fieldGetStaticValue(const DotNetProcess *process, const DotNetField *field, uint64_t *output_ptr);
    void classPrintFields(DotNetClass *klass);

#ifdef __cplusplus
}
#endif

#endif // DOTNET_REFLECTION_H