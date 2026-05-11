#include <windows.h>
#include <sstream>
#include <string>

#include <hook_utils.h>
#include <sc2kfix.h>

// ----------------------------------------------------------------
// Internal shared implementation — all patch types go through this
// ----------------------------------------------------------------
static bool UnprotectAndPatch(
    LPVOID targetAddress,
    SIZE_T patchSize,
    const char* debugName,
    void (*writeFn)(LPVOID, void*),  // the actual write operation
    void* writeParam)
{
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(targetAddress, &mbi, sizeof(mbi)) == 0) {
        // log error
        return false;
    }

    if (mbi.State != MEM_COMMIT) {
        // log error: not committed
        return false;
    }

    // Handle page boundary straddling
    uintptr_t addr = (uintptr_t)targetAddress;
    uintptr_t firstPage = addr & ~(uintptr_t)(0xFFF);
    uintptr_t lastPage = (addr + patchSize - 1) & ~(uintptr_t)(0xFFF);
    SIZE_T regionSize = (lastPage - firstPage) + 0x1000;

    DWORD dwOldProtect = 0, dwDummy = 0;
    if (!VirtualProtect((LPVOID)firstPage, regionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        // log error
        return false;
    }

    // do the actual patch
    writeFn(targetAddress, writeParam);  

    VirtualProtect((LPVOID)firstPage, regionSize, dwOldProtect, &dwDummy);
    FlushInstructionCache(GetCurrentProcess(), targetAddress, patchSize);

    OutputDebugStringA(("[Hook OK] " + std::string(debugName) + "\n").c_str());
    return true;
}

// ----------------------------------------------------------------
// JMP patch
// ----------------------------------------------------------------
struct JmpParam { LPVOID hookFn; };

static void WriteJmp(LPVOID target, void* param) {
    JmpParam* p = (JmpParam*)param;
    NEWJMP(target, p->hookFn);
}

bool SafePatchJmp(LPVOID targetAddress, LPVOID hookFunction, const char* debugName) {
    JmpParam p = { hookFunction };
    return UnprotectAndPatch(targetAddress, 5, debugName, WriteJmp, &p);
}

// ----------------------------------------------------------------
// NOP patch (0x90)
// ----------------------------------------------------------------
struct NopParam { SIZE_T size; };

static void WriteNop(LPVOID target, void* param) {
    NopParam* p = (NopParam*)param;
    memset(target, 0x90, p->size);
}

bool SafePatchNop(LPVOID targetAddress, SIZE_T size, const char* debugName) {
    NopParam p = { size };
    return UnprotectAndPatch(targetAddress, size, debugName, WriteNop, &p);
}

// ----------------------------------------------------------------
// Arbitrary bytes patch
// ----------------------------------------------------------------
struct BytesParam { const BYTE* bytes; SIZE_T size; };

static void WriteBytes(LPVOID target, void* param) {
    BytesParam* p = (BytesParam*)param;
    memcpy(target, p->bytes, p->size);
}

bool SafePatchByte(LPVOID targetAddress, BYTE value, const char* debugName) {
    return SafePatchBytes(targetAddress, &value, 1, debugName);
}

bool SafePatchBytes(LPVOID targetAddress, const BYTE* bytes, SIZE_T size, const char* debugName) {
    BytesParam p = { bytes, size };
    return UnprotectAndPatch(targetAddress, size, debugName, WriteBytes, &p);
}

