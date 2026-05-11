#pragma once
#include <windows.h>

// Patch a 5-byte JMP to a hook function
bool SafePatchJmp(
	LPVOID targetAddress,
	LPVOID hookFunction,
	const char* debugName
);

// NOP out a region of code
bool SafePatchNop(
	LPVOID targetAddress, 
	SIZE_T size,
	const char* debugName
);

// Calls SafePatchBytes with just 1 byte
bool SafePatchByte(
	LPVOID targetAddress,
	BYTE value,
	const char* debugName
);

// Write arbitrary bytes (for CALL patches, data patches etc)
bool SafePatchBytes(
	LPVOID targetAddress,
	const BYTE* bytes,
	SIZE_T size,
	const char* debugName
);
