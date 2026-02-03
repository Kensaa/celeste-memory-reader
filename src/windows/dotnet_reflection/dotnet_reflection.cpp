#include "dotnet_reflection.h"
#include <stdio.h>
#include <windows.h>
#include <cor.h>
#include <cordebug.h>
#include <metahost.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <map>
#include <guiddef.h>
#include <clrdata.h>

typedef HRESULT (*ENUMERATECLRS)(DWORD debuggeePID,
                                 HANDLE **ppHandleArrayOut,
                                 LPWSTR **ppStringArrayOut,
                                 DWORD *pdwArrayLengthOut);

typedef HRESULT (*CREATEVERSIONSTRINGFROMMODULE)(
    DWORD pidDebuggee,
    LPCWSTR szModuleName,
    LPWSTR Buffer,
    DWORD cchBuffer,
    DWORD *pdwLength);

typedef HRESULT (*CREATEDEBUGGINGINTERFACEFROMVERSION2)(LPCWSTR szDebuggeeVersion, IUnknown **ppCordb);
ENUMERATECLRS EnumerateCLRs;
CREATEVERSIONSTRINGFROMMODULE CreateVersionStringFromModule;
CREATEDEBUGGINGINTERFACEFROMVERSION2 CreateDebuggingInterfaceFromVersion2;

class SimpleCLRLibraryProvider : public ICLRDebuggingLibraryProvider
{
private:
    LONG refCount;
    ICLRRuntimeInfo *RuntimeInfo;
    WCHAR dotnetPath[MAX_PATH]; // Path to .NET runtime directory

public:
    SimpleCLRLibraryProvider(ICLRRuntimeInfo *rti, const WCHAR *runtimePath = NULL) : refCount(1)
    {
        RuntimeInfo = rti;
        if (runtimePath && wcslen(runtimePath) > 0)
        {
            wcscpy_s(dotnetPath, MAX_PATH, runtimePath);
        }
        else
        {
            dotnetPath[0] = L'\0';
        }
    }

    // IUnknown methods
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject)
    {
        if (riid == IID_IUnknown || riid == IID_ICLRDebuggingLibraryProvider)
        {
            *ppvObject = this;
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    virtual ULONG STDMETHODCALLTYPE AddRef()
    {
        return InterlockedIncrement(&refCount);
    }

    virtual ULONG STDMETHODCALLTYPE Release()
    {
        LONG count = InterlockedDecrement(&refCount);
        if (count == 0)
        {
            delete this;
        }
        return count;
    }

    // ICLRDebuggingLibraryProvider method
    virtual HRESULT STDMETHODCALLTYPE ProvideLibrary(
        const WCHAR *pwszFileName,
        DWORD dwTimestamp,
        DWORD dwSizeOfImage,
        HMODULE *phModule)
    {
        // The CLR is asking us to load a debugging library
        // Usually this is "mscordbi.dll" or "mscordacwks.dll"

        HRESULT r;
        if (RuntimeInfo)
        {
            r = RuntimeInfo->LoadLibrary(pwszFileName, phModule);
        }
        else
        {
            r = E_NOTIMPL;
        }

        if (r == S_OK)
        {
            return S_OK;
        }
        else
        {
            return E_FAIL;
        }
    }
};

// ============================================
// Data Target - Memory Reading Callback
// ============================================

// The CLR debugging API also needs this to read memory from the target process
class SimpleCLRDataTarget : public ICorDebugDataTarget
{
private:
    LONG refCount;
    HANDLE processHandle;

public:
    SimpleCLRDataTarget(HANDLE hProcess) : refCount(1), processHandle(hProcess) {}

    // IUnknown methods
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject)
    {
        if (riid == IID_IUnknown || riid == IID_ICorDebugDataTarget)
        {
            *ppvObject = this;
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    virtual ULONG STDMETHODCALLTYPE AddRef()
    {
        return InterlockedIncrement(&refCount);
    }

    virtual ULONG STDMETHODCALLTYPE Release()
    {
        LONG count = InterlockedDecrement(&refCount);
        if (count == 0)
        {
            delete this;
        }
        return count;
    }

    // ICorDebugDataTarget methods
    virtual HRESULT STDMETHODCALLTYPE GetPlatform(CorDebugPlatform *pTargetPlatform)
    {
// Tell the debugger what platform we're on
#ifdef _WIN64
        *pTargetPlatform = CORDB_PLATFORM_WINDOWS_AMD64;
#else
        *pTargetPlatform = CORDB_PLATFORM_WINDOWS_X86;
#endif
        return S_OK;
    }

    virtual HRESULT STDMETHODCALLTYPE ReadVirtual(
        CORDB_ADDRESS address,
        BYTE *pBuffer,
        ULONG32 bytesRequested,
        ULONG32 *pBytesRead)
    {
        // Read memory from the target process
        SIZE_T bytesRead;
        if (ReadProcessMemory(processHandle, (LPCVOID)address, pBuffer, bytesRequested, &bytesRead))
        {
            if (pBytesRead)
                *pBytesRead = (ULONG32)bytesRead;
            return S_OK;
        }
        return E_FAIL;
    }

    virtual HRESULT STDMETHODCALLTYPE GetThreadContext(
        DWORD dwThreadID,
        ULONG32 contextFlags,
        ULONG32 contextSize,
        BYTE *pContext)
    {
        // Not needed for basic memory reading
        return E_NOTIMPL;
    }
};

struct DotNetField
{
    std::string name;
    std::string type_name;
    uint32_t offset;
    bool is_static;
    mdFieldDef token;
    ICorDebugModule *parent_module;
    mdTypeDef parent_class_token;
    // ICorDebugClass *parent_debug_class; // For static field access
    // ICorDebugModule *parent_module; // For static field access

    ~DotNetField()
    {
    }
};

struct DotNetClass
{
    std::string name;
    std::string namespace_name;
    std::string full_name;
    mdTypeDef token;
    uint32_t size;
    ICorDebugClass *debug_class;
    ICorDebugClass2 *debug_class2;
    ICorDebugModule *debug_module;
    IMetaDataImport *metadata;
    std::vector<DotNetField *> fields;
    DotNetProcess *process;

    ~DotNetClass()
    {
        for (auto field : fields)
        {
            delete field;
        }
        if (debug_class)
            debug_class->Release();
        if (debug_class2)
            debug_class2->Release();
        if (debug_module)
            debug_module->Release();
        if (metadata)
            metadata->Release();
    }
};

struct DotNetProcess
{
    HANDLE process_handle;
    uint32_t process_id;
    ICorDebugProcess *cor_debug_process;
    ICorDebugProcess5 *cor_debug_process5;
    std::map<std::string, DotNetClass *> class_cache;

    ~DotNetProcess()
    {
        for (auto &pair : class_cache)
        {
            delete pair.second;
        }
        if (cor_debug_process5)
            cor_debug_process5->Release();
        if (cor_debug_process)
            cor_debug_process->Release();
        if (process_handle)
            CloseHandle(process_handle);
    }
};

static bool attachProcess(DotNetProcess *process)
{

    CLR_DEBUGGING_VERSION v;
    v.wStructVersion = 0;
    v.wMajor = 4;
    v.wMinor = 0;
    v.wRevision = 30319;
    v.wBuild = 65535;

    ICLRMetaHost *pMetaHost;
    ICLRDebugging *CLRDebugging = NULL;

    HMODULE hMscoree = LoadLibraryA("mscoree.dll");
    if (!hMscoree)
    {
        // printf("could not find mscoree\n");
        return false;
    }
    CLRCreateInstanceFnPtr CLRCreateInstance = NULL;
    CLRCreateInstance = (CLRCreateInstanceFnPtr)GetProcAddress(hMscoree, "CLRCreateInstance");
    if (!CLRCreateInstance)
    {
        // printf("could not find CLRCreateInstance\n");
        return false;
    }

    SimpleCLRLibraryProvider *libProvider;
    IEnumUnknown *RuntimeEnum;
    if (CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID *)&pMetaHost) == S_OK)
    {
        if (pMetaHost->EnumerateLoadedRuntimes(process->process_handle, &RuntimeEnum) == S_OK)
        {
            ICLRRuntimeInfo *info;
            ULONG count = 0;

            RuntimeEnum->Next(1, (IUnknown **)&info, &count);
            if (count)
            {
                libProvider = new SimpleCLRLibraryProvider(info);
            }

            RuntimeEnum->Release();
        }

        pMetaHost->Release();
    }

    CLRCreateInstance(CLSID_CLRDebugging, IID_ICLRDebugging, (void **)&CLRDebugging);
    SimpleCLRDataTarget *dataTarget;

    HANDLE ths = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process->process_id);
    if (ths == INVALID_HANDLE_VALUE)
    {
        // printf("failed snapshot\n");
        return false;
    }

    // ICorDebugProcess *corDebugProcess = NULL;
    // ICorDebugProcess5 *corDebugProcess5 = NULL;

    MODULEENTRY32 m;
    ZeroMemory(&m, sizeof(m));
    m.dwSize = sizeof(m);
    if (Module32First(ths, &m))
    {
        dataTarget = new SimpleCLRDataTarget(process->process_handle);

        do
        {
            CLR_DEBUGGING_PROCESS_FLAGS flags;
            HRESULT r = CLRDebugging->OpenVirtualProcess((ULONG64)m.hModule, dataTarget, libProvider, &v, IID_ICorDebugProcess, (IUnknown **)&process->cor_debug_process, &v, &flags);
            if (r == S_OK)
            {
                process->cor_debug_process->QueryInterface(IID_ICorDebugProcess5, (void **)&process->cor_debug_process5);
                break;
            }

        }

        while (Module32Next(ths, &m));
    }

    CloseHandle(ths);

    if (!process->cor_debug_process)
    {
        // printf("no cor debug process\n");
        return false;
    }

    return true;
}

DotNetProcess *openProcess(uint32_t process_id)
{
    DotNetProcess *process = new DotNetProcess();
    process->process_id = process_id;
    process->process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process->process_id);
    if (process->process_handle == 0)
    {
        delete process;
        return NULL;
    }
    if (!attachProcess(process))
    {
        delete process;
        return NULL;
    }

    return process;
}

void *getProcessHandle(DotNetProcess *process)
{
    return process->process_handle;
}

void closeProcess(DotNetProcess *process)
{
    delete process;
}

uint32_t findProcess(const char *name)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    WCHAR wname[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, MAX_PATH);

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snapshot, &pe))
    {
        do
        {
            if (wcscmp(pe.szExeFile, wname) == 0)
            {
                CloseHandle(snapshot);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return 0;
}

static std::string WideToUtf8(const WCHAR *wide)
{
    if (!wide)
        return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
    if (len <= 0)
        return "";
    std::string result(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, &result[0], len, NULL, NULL);
    return result;
}

static COR_TYPEID getCOR_TYPEID(ICorDebugModule *module, mdTypeDef TypeDef)
{
    COR_TYPEID result = {0, 0};

    ICorDebugClass *ppClass = NULL;
    ICorDebugClass2 *ppClass2 = NULL;
    ICorDebugType *ppType = NULL;
    ICorDebugType2 *ppType2 = NULL; // Q:"It doesn't compile <insert crying corgi pic>"  A: update your .net include and library to .net 4.6.2 or later

    if (module->GetClassFromToken(TypeDef, &ppClass) == S_OK)
    {
        if (ppClass && (ppClass->QueryInterface(IID_ICorDebugClass2, (void **)&ppClass2) == S_OK))
        {

            if (ppClass2 && (ppClass2->GetParameterizedType(ELEMENT_TYPE_CLASS, 0, NULL, &ppType) == S_OK)) // todo: generics
            {
                if (ppType && (ppType->QueryInterface(IID_ICorDebugType2, (void **)&ppType2) == S_OK))
                {
                    HRESULT hr;
                    hr = ppType2->GetTypeID(&result);

                    if (hr == S_OK)
                    {
                        return result;
                    }
                }
            }
        }
    }

    return {0, 0};
}

static IMetaDataImport *getMetaDataFromTypeID(ICorDebugProcess5 *process5, COR_TYPEID type_id)
{

    ICorDebugType *type;
    ICorDebugClass *c;
    ICorDebugModule *m;
    IMetaDataImport *metadata = NULL;

    if (process5->GetTypeForTypeID(type_id, &type) == S_OK)
    {
        if (type->GetClass(&c) == S_OK)
        {
            if (c->GetModule(&m) == S_OK)
            {
                m->GetMetaDataInterface(IID_IMetaDataImport, (IUnknown **)&metadata);
                m->Release();
            }
            c->Release();
        }
        type->Release();
    }

    return metadata;
}

ICorDebugModule *getModuleFromTypeID(ICorDebugProcess5 *process5, COR_TYPEID type_id)
{
    ICorDebugModule *m = NULL;
    ICorDebugType *type;
    ICorDebugClass *c;
    if (process5->GetTypeForTypeID(type_id, &type) == S_OK)
    {

        if (type->GetClass(&c) == S_OK)
        {
            c->GetModule(&m);
            c->Release();
        }
        type->Release();
    }

    return m;
}
mdTypeDef getClassTokenFromTypeID(ICorDebugProcess5 *process5, COR_TYPEID type_id)
{
    ICorDebugType *type;
    ICorDebugClass *c;
    mdTypeDef token;
    if (process5->GetTypeForTypeID(type_id, &type) == S_OK)
    {

        if (type->GetClass(&c) == S_OK)
        {
            c->GetToken(&token);
            c->Release();
        }
        type->Release();
    }

    return token;
}
static void enumerateClassFields(ICorDebugProcess5 *process5, ICorDebugModule *module, mdTypeDef typeDef, std::vector<DotNetField *> *outFields)
{
    COR_TYPEID id = getCOR_TYPEID(module, typeDef);

    IMetaDataImport *metadata = getMetaDataFromTypeID(process5, id);
    COR_TYPE_LAYOUT layout;
    if (process5->GetTypeLayout(id, &layout) != S_OK)
    {
        metadata->Release();
        return;
    }

    if (layout.parentID.token1 || layout.parentID.token2)
    {
        // TODO
        COR_TYPE_LAYOUT layoutparent;
        if (process5->GetTypeLayout(layout.parentID, &layoutparent) == S_OK)
        {
            enumerateClassFields(process5, getModuleFromTypeID(process5, layout.parentID), getClassTokenFromTypeID(process5, layout.parentID), outFields);
        }
    }

    COR_FIELD *fieldsArray = (COR_FIELD *)malloc(sizeof(COR_FIELD) * layout.numFields);
    ULONG32 fieldcount;

    if (process5->GetTypeFields(id, layout.numFields, fieldsArray, &fieldcount) != S_OK)
    {

        metadata->Release();
        free(fieldsArray);
        return;
    }

    std::vector<COR_FIELD> fields;

    for (size_t i = 0; i < fieldcount; i++)
    {
        fields.push_back(fieldsArray[i]);
    }

    if (fieldsArray)
        free(fieldsArray);

    HCORENUM hEnum = NULL;
    mdFieldDef metaFields[256];
    ULONG count;
    while (metadata->EnumFields(&hEnum, typeDef, metaFields, 256, &count) == S_OK && count > 0)
    {
        for (int j = 0; j < count; j++)
        {
            int k;
            int found = 0;
            for (k = 0; k < fieldcount; k++)
            {
                if (metaFields[j] == fields[k].token)
                {
                    found = 1;
                    break;
                }
            }

            if (!found)
            {
                // TODO: CHANGE THIS
                COR_FIELD dummy;

                dummy.fieldType = ELEMENT_TYPE_END;
                dummy.id = {0, 0};
                dummy.offset = 0;
                dummy.token = metaFields[j];
                fields.push_back(dummy);
                fieldcount++;
            }
        }
    }

    for (int i = 0; i < fields.size(); i++)
    {
        mdTypeDef classtype;
        WCHAR fieldName[256];
        ULONG nameLen;
        DWORD flags;
        PCCOR_SIGNATURE sig;
        ULONG sigLen;
        DWORD cplusTypeFlag;
        UVCP_CONSTANT defaultValue;
        ULONG defaultValueLen;
        if (metadata->GetFieldProps(fields[i].token, &classtype, fieldName, 256, &nameLen, &flags, &sig, &sigLen, &cplusTypeFlag, &defaultValue, &defaultValueLen) == S_OK)
        {
            DotNetField *field = new DotNetField();

            field->name = WideToUtf8(fieldName);
            field->is_static = IsFdStatic(flags);
            field->offset = fields[i].offset;
            field->parent_class_token = typeDef;
            field->parent_module = module;
            field->token = fields[i].token;

            CorElementType fieldType = field->is_static ? (CorElementType)cplusTypeFlag : fields[i].fieldType;
            const BYTE *p = sig;
            if (sigLen >= 2)
            {
                if ((*p & IMAGE_CEE_CS_CALLCONV_MASK) == IMAGE_CEE_CS_CALLCONV_FIELD)
                {
                    p++;
                    p += CorSigUncompressElementType(p, &fieldType);
                }
            }
            switch (fieldType)
            {
            case ELEMENT_TYPE_END:
                field->type_name = "end";
                break;
            case ELEMENT_TYPE_VOID:
                field->type_name = "void";
                break;
            case ELEMENT_TYPE_BOOLEAN:
                field->type_name = "bool";
                break;
            case ELEMENT_TYPE_CHAR:
                field->type_name = "char";
                break;
            case ELEMENT_TYPE_I1:
                field->type_name = "sbyte";
                break;
            case ELEMENT_TYPE_U1:
                field->type_name = "byte";
                break;
            case ELEMENT_TYPE_I2:
                field->type_name = "short";
                break;
            case ELEMENT_TYPE_U2:
                field->type_name = "ushort";
                break;
            case ELEMENT_TYPE_I4:
                field->type_name = "int";
                break;
            case ELEMENT_TYPE_U4:
                field->type_name = "uint";
                break;
            case ELEMENT_TYPE_I8:
                field->type_name = "long";
                break;
            case ELEMENT_TYPE_U8:
                field->type_name = "ulong";
                break;
            case ELEMENT_TYPE_R4:
                field->type_name = "float";
                break;
            case ELEMENT_TYPE_R8:
                field->type_name = "double";
                break;
            case ELEMENT_TYPE_STRING:
                field->type_name = "string";
                break;
            case ELEMENT_TYPE_PTR:
                field->type_name = "ptr";
                break;
            case ELEMENT_TYPE_BYREF:
                field->type_name = "byref";
                break;
            case ELEMENT_TYPE_CLASS:
                field->type_name = "object";
                break;
            case ELEMENT_TYPE_VALUETYPE:
                field->type_name = "struct";
                break;
            case ELEMENT_TYPE_VAR:
                field->type_name = "var";
                break;
            case ELEMENT_TYPE_ARRAY:
                field->type_name = "array";
                break;
            case ELEMENT_TYPE_GENERICINST:
                field->type_name = "genericInst";
                break;
            case ELEMENT_TYPE_TYPEDBYREF:
                field->type_name = "typedbyref";
                break;
            case ELEMENT_TYPE_I:
                field->type_name = "native int";
                break;
            case ELEMENT_TYPE_U:
                field->type_name = "native uint";
                break;
            case ELEMENT_TYPE_FNPTR:
                field->type_name = "fn ptr";
                break;
            case ELEMENT_TYPE_OBJECT:
                field->type_name = "object";
                break;
            case ELEMENT_TYPE_SZARRAY:
                field->type_name = "szarray";
                break;
            default:
                field->type_name = "unknown";
                break;
            }

            if (field->is_static && (fieldType == ELEMENT_TYPE_CLASS || fieldType == ELEMENT_TYPE_VALUETYPE))
            {
                mdToken typeToken;
                p += CorSigUncompressToken(p, &typeToken);

                WCHAR typeName[256];
                ULONG typeNameLen;
                DWORD flags;
                mdToken extends;

                if (TypeFromToken(typeToken) == mdtTypeDef)
                {
                    metadata->GetTypeDefProps(
                        typeToken,
                        typeName,
                        256,
                        &typeNameLen,
                        &flags,
                        &extends);
                }
                else if (TypeFromToken(typeToken) == mdtTypeRef)
                {
                    metadata->GetTypeRefProps(
                        typeToken,
                        nullptr,
                        typeName,
                        256,
                        &typeNameLen);
                }
                field->type_name = WideToUtf8(typeName);
            }
            else
            {
                ICorDebugType *type2;
                if ((fields[i].id.token1 || fields[i].id.token2) && (process5->GetTypeForTypeID(fields[i].id, &type2) == S_OK))
                {
                    if (type2)
                    {
                        ICorDebugClass *c2;

                        if (type2->GetClass(&c2) == S_OK)
                        {
                            mdTypeDef classtoken;
                            if (c2->GetToken(&classtoken) == S_OK)
                            {
                                ICorDebugModule *m2;
                                if (c2->GetModule(&m2) == S_OK)
                                {
                                    IMetaDataImport *metadata2 = NULL;
                                    m2->GetMetaDataInterface(IID_IMetaDataImport, (IUnknown **)&metadata2);
                                    if (metadata2)
                                    {
                                        DWORD flags2;
                                        mdToken extends2;
                                        WCHAR classname[255];
                                        ULONG classnamelength;
                                        metadata2->GetTypeDefProps(classtoken, classname, 255, &classnamelength, &flags2, &extends2);
                                        field->type_name = WideToUtf8(classname);
                                    }

                                    m2->Release();
                                }
                                c2->Release();
                            }
                        }

                        type2->Release();
                    }
                }
            }

            outFields->push_back(field);
        }
    }
    metadata->Release();
}

static DotNetClass *findClassInModule(DotNetProcess *process, ICorDebugModule *module, const char *class_name)
{
    IUnknown *metadataImport = NULL;
    if (module->GetMetaDataInterface(IID_IMetaDataImport, &metadataImport) != S_OK)
        return NULL;

    IMetaDataImport *import = NULL;
    metadataImport->QueryInterface(IID_IMetaDataImport, (void **)&import);

    DotNetClass *result = NULL;
    if (import)
    {
        HCORENUM hEnum = NULL;
        mdTypeDef typeDefs[256];
        ULONG count;

        while (import->EnumTypeDefs(&hEnum, typeDefs, 256, &count) == S_OK && count > 0)
        {
            for (ULONG i = 0; i < count; i++)
            {
                mdTypeDef typeDef = typeDefs[i];
                WCHAR className[256];
                ULONG nameLen;
                DWORD flags;
                mdToken extends;
                if (import->GetTypeDefProps(typeDefs[i], className, 256, &nameLen, &flags, &extends) == S_OK)
                {
                    std::string classNameStr = WideToUtf8(className);
                    if (classNameStr == class_name)
                    {
                        DotNetClass *klass = new DotNetClass();
                        klass->process = process;
                        klass->full_name = classNameStr;
                        size_t dot_pos = classNameStr.rfind('.');
                        if (dot_pos != std::string::npos)
                        {
                            klass->namespace_name = classNameStr.substr(0, dot_pos);
                            klass->name = classNameStr.substr(dot_pos + 1);
                        }
                        else
                        {
                            klass->namespace_name = "";
                            klass->name = classNameStr;
                        }

                        klass->token = typeDef;
                        klass->metadata = import;
                        klass->metadata->AddRef();

                        module->GetClassFromToken(typeDef, &klass->debug_class);
                        klass->debug_class->QueryInterface(IID_ICorDebugClass2, (void **)&klass->debug_class2);

                        klass->debug_module = module;
                        klass->debug_module->AddRef();

                        COR_TYPE_LAYOUT layout;
                        if (process->cor_debug_process5->GetTypeLayout(getCOR_TYPEID(module, typeDef), &layout) != S_OK)
                        {
                            delete klass;
                            continue;
                        }
                        klass->size = layout.objectSize;
                        enumerateClassFields(process->cor_debug_process5, module, typeDef, &klass->fields);

                        result = klass;
                        break;
                    }
                }
            }
            if (result)
                break;
        }
        if (hEnum)
            import->CloseEnum(hEnum);
        if (!result)
            import->Release();
    }

    metadataImport->Release();
    return result;
}

DotNetClass *findClass(DotNetProcess *process, const char *class_name)
{
    if (!process || !process->cor_debug_process)
    {
        return NULL;
    }

    auto it = process->class_cache.find(class_name);
    if (it != process->class_cache.end())
    {
        return it->second;
    }

    ICorDebugAppDomainEnum *domainEnum = NULL;
    HRESULT hr = process->cor_debug_process->EnumerateAppDomains(&domainEnum);

    if (FAILED(hr) || !domainEnum)
    {
        return NULL;
    }

    DotNetClass *result = NULL;
    ULONG domainCount;
    ICorDebugAppDomain *domain;
    while (domainEnum->Next(1, &domain, &domainCount) == S_OK && domainCount > 0)
    {
        ICorDebugAssemblyEnum *assemblyEnum = NULL;
        if (domain->EnumerateAssemblies(&assemblyEnum) == S_OK)
        {
            ULONG assemblyCount;
            ICorDebugAssembly *assembly;

            while (assemblyEnum->Next(1, &assembly, &assemblyCount) == S_OK && assemblyCount > 0)
            {
                ICorDebugModuleEnum *moduleEnum = NULL;
                if (assembly->EnumerateModules(&moduleEnum) == S_OK)
                {
                    ICorDebugModule *module;
                    ULONG moduleCount;
                    while (moduleEnum->Next(1, &module, &moduleCount) == S_OK && moduleCount > 0)
                    {
                        // ULONG32 nameSize;
                        // WCHAR name[255];
                        // module->GetName(255, &nameSize, name);
                        // printf("module name : %ls\n", name);

                        result = findClassInModule(process, module, class_name);
                        module->Release();
                        if (result)
                            break;
                    }
                    moduleEnum->Release();
                }

                assembly->Release();
                if (result)
                    break;
            }
            assemblyEnum->Release();
        }
        domain->Release();
        if (result)
            break;
    }
    domainEnum->Release();

    // Add to cache
    if (result)
    {
        process->class_cache[class_name] = result;
    }
    return result;
}

const char *classGetName(const DotNetClass *klass)
{
    return klass ? klass->name.c_str() : NULL;
}
const char *classGetNamespace(const DotNetClass *klass)
{
    return klass ? klass->namespace_name.c_str() : NULL;
}
const char *classGetFullName(const DotNetClass *klass)
{
    return klass ? klass->full_name.c_str() : NULL;
}
uint32_t classGetSize(const DotNetClass *klass)
{
    return klass ? klass->size : 0;
}

DotNetField *classFindField(const DotNetClass *klass, const char *field_name)
{
    if (!klass)
        return NULL;

    for (auto field : klass->fields)
    {
        if (field->name == field_name)
        {
            return field;
        }
    }

    return NULL;
}

const char *fieldGetName(const DotNetField *field)
{
    return field ? field->name.c_str() : NULL;
}

uint32_t fieldGetOffset(const DotNetField *field)
{
    return field ? field->offset : 0;
}

bool fieldIsStatic(const DotNetField *field)
{
    return field ? field->is_static : false;
}

const char *fieldGetTypeName(const DotNetField *field)
{
    return field ? field->type_name.c_str() : NULL;
}

bool fieldGetStaticValue(const DotNetProcess *process, const DotNetField *field, uint64_t *output_ptr)
{
    if (!process || !field || !field->is_static)
    {
        return false;
    }

    ICorDebugClass *parentClass;
    field->parent_module->GetClassFromToken(field->parent_class_token, &parentClass);
    ICorDebugValue *pValue = NULL;
    HRESULT hr =
        parentClass->GetStaticFieldValue(field->token, NULL, &pValue);
    if (hr != S_OK || !pValue)
    {
        parentClass->Release();
        printf("%d\n", hr != S_OK);
        return false;
    }
    ICorDebugReferenceValue *pRefValue = NULL;
    hr = pValue->QueryInterface(IID_ICorDebugReferenceValue, (void **)&pRefValue);

    if (hr == S_OK && pRefValue)
    {
        CORDB_ADDRESS addr;
        hr = pRefValue->GetValue(&addr);
        parentClass->Release();
        pRefValue->Release();
        pValue->Release();

        if (SUCCEEDED(hr))
        {
            *output_ptr = addr;
            return true;
        }
    }
    else
    {
        pValue->Release();
    }

    parentClass->Release();
    return false;
}
void classPrintFields(DotNetClass *klass)
{
    for (int i = 0; i < klass->fields.size(); i++)
    {
        DotNetField *field = klass->fields[i];
        printf("name : %s, is_static: %d, offset : %d, type_name : %s\n", field->name.c_str(), field->is_static, field->offset, field->type_name.c_str());
    }
}