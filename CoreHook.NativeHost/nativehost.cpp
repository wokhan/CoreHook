// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

// Headers for this file
#include "nativehost.h"

// Standard headers
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <iostream>
#include <vector>
#include <comdef.h>
#include <comutil.h>

// Provided by the AppHost NuGet package and installed as an SDK pack
#include "nethost.h"
#include "coreclr_delegates.h"
#include "hostfxr.h"

#ifdef WINDOWS
#include <Windows.h>

#define STR(s) L ## s
#define CH(c) L ## c
#define DIR_SEPARATOR L'\\'

#else
#include <dlfcn.h>
#include <limits.h>

#define STR(s) s
#define CH(c) c
#define DIR_SEPARATOR '/'
#define MAX_PATH PATH_MAX

#endif

//using string_t = std::basic_string<char_t>;

typedef int (CORECLR_DELEGATE_CALLTYPE load_plugin_fn)(const void* ptr);

// Globals to hold hostfxr exports
hostfxr_initialize_for_runtime_config_fn init_fptr;
hostfxr_get_runtime_delegate_fn get_delegate_fptr;
hostfxr_close_fn close_fptr;

// Forward declarations
bool load_hostfxr();
load_assembly_and_get_function_pointer_fn get_dotnet_load_assembly(const char_t* assembly);

/********************************************************************************************
 * Function used to load and activate .NET Core
 ********************************************************************************************/

 // Forward declarations
void* load_library(const char_t*);
void* get_export(void*, const char*);

void* load_library(const char_t* path)
{
#ifdef WINDOWS
	HMODULE h = ::LoadLibraryW(path);
#else
	void* h = dlopen(path, RTLD_LAZY | RTLD_LOCAL);
#endif
	assert(h != nullptr);
	return (void*)h;
}

void* get_export(void* h, const char* name)
{
#ifdef WINDOWS
	void* f = ::GetProcAddress((HMODULE)h, name);
#else
	void* f = dlsym(h, name);
#endif
	assert(f != nullptr);
	return f;
}

// <SnippetLoadHostFxr>
// Using the nethost library, discover the location of hostfxr and get exports
bool load_hostfxr()
{
	// Pre-allocate a large buffer for the path to hostfxr
	char_t buffer[MAX_PATH];
	size_t buffer_size = sizeof(buffer) / sizeof(char_t);

	int rc = get_hostfxr_path(buffer, &buffer_size, nullptr);
	switch (rc) {
	case 0x00000000:
		// Log
		break;

	case 0x80008098: // HostApiBufferTooSmall: The buffer specified to an API is not big enough to fit the requested value
	default:
		return false;
		break;

	}

	// Load hostfxr and get desired exports
	void* lib = load_library(buffer);
	init_fptr = (hostfxr_initialize_for_runtime_config_fn)get_export(lib, "hostfxr_initialize_for_runtime_config");
	get_delegate_fptr = (hostfxr_get_runtime_delegate_fn)get_export(lib, "hostfxr_get_runtime_delegate");
	close_fptr = (hostfxr_close_fn)get_export(lib, "hostfxr_close");

	return (init_fptr && get_delegate_fptr && close_fptr);
}
// </SnippetLoadHostFxr>

// <SnippetInitialize>
// Load and initialize .NET Core and get desired function pointer for scenario
load_assembly_and_get_function_pointer_fn get_dotnet_load_assembly(const char_t* config_path, HANDLE pipeHandle)
{
	// Load .NET Core
	void* load_assembly_and_get_function_pointer = nullptr;
	hostfxr_handle cxt = nullptr;
	int rc = init_fptr(config_path, nullptr, &cxt);

	switch (rc) {
	case 0x00000000: // Success: Hosting components were successfully initialized 
		WriteToPipe(pipeHandle, LOG_LEVEL_INFO, "Success: Hosting components were successfully initialized");
		break;

	case 0x00000001: // Success_HostAlreadyInitialized: Config is compatible with already initialized hosting components
		WriteToPipe(pipeHandle, LOG_LEVEL_INFO, "Success_HostAlreadyInitialized: Config is compatible with already initialized hosting components");
		break;

	case 0x00000002: // Success_DifferentRuntimeProperties: Config has runtime properties that differ from already initialized hosting components
		WriteToPipe(pipeHandle, LOG_LEVEL_INFO, "Success_DifferentRuntimeProperties: Config has runtime properties that differ from already initialized hosting components");
		break;

	case 0x800080a5: // CoreHostIncompatibleConfig: Config is incompatible with already initialized hosting components
		WriteToPipe(pipeHandle, LOG_LEVEL_ERROR, "CoreHostIncompatibleConfig: Config is incompatible with already initialized hosting components");
		close_fptr(cxt);
		return nullptr;

	case 0x80008093: // InvalidConfigFile: The .runtimeconfig.json file is invalid
		WriteToPipe(pipeHandle, LOG_LEVEL_ERROR, "InvalidConfigFile: The .runtimeconfig.json file is invalid");
		close_fptr(cxt);
		return nullptr;
		
	default:
		close_fptr(cxt);
		return nullptr;
	}

	WriteToPipe(pipeHandle, LOG_LEVEL_INFO, "Retrieving the function pointer...");

	// Get the load assembly function pointer
	rc = get_delegate_fptr(cxt, hdt_load_assembly_and_get_function_pointer, &load_assembly_and_get_function_pointer);

	switch (rc) {
	case 0x00000000: // Success
		break;

	case 0x800080a6: // HostApiUnsupportedScenario: the given delegate type is not supported using the given context
		WriteToPipe(pipeHandle, LOG_LEVEL_ERROR, "HostApiUnsupportedScenario: the given delegate type is not supported using the given context");
		break;

	case 0x800080a7: // HostFeatureDisabled: managed feature support for native host is disabled
		WriteToPipe(pipeHandle, LOG_LEVEL_ERROR, "HostFeatureDisabled: managed feature support for native host is disabled");
		break;
	}

	WriteToPipe(pipeHandle, LOG_LEVEL_INFO, "Function is ready.");

	close_fptr(cxt);

	return (load_assembly_and_get_function_pointer_fn)load_assembly_and_get_function_pointer;
}

bool inline check_arg_length(const wchar_t* argument, size_t max_size)
{
	return (argument == nullptr || wcsnlen(argument, max_size) >= max_size) ? false : true;
}

static load_assembly_and_get_function_pointer_fn load_assembly_and_get_function_pointer = nullptr;

// Host the .NET Core runtime in the current application
SHARED_API int StartCoreCLR(const core_host_arguments* arguments)
{
	if (arguments == nullptr
		|| !check_arg_length(arguments->assembly_file_path /* CoreHook.CoreLoader.dll */, MAX_PATH)
		|| !check_arg_length(arguments->core_root_path /* Current folder if standalone */, MAX_PATH))
	{
		return 1;// coreload::StatusCode::InvalidArgFailure;
	}

	std::wstring pipename = arguments->pipename;
	HANDLE pipeHandle = CreateFile((STR("\\\\.\\pipe\\") + pipename).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);

	WriteToPipe(pipeHandle, LOG_LEVEL_INFO, "CoreHook.NativeHost successfully loaded! Now starting the .NET Host.");

	// STEP 1: Load HostFxr and get exported hosting functions
	if (!load_hostfxr())
	{
		assert(false && "Failure: load_hostfxr()");
		WriteToPipe(pipeHandle, LOG_LEVEL_INFO, "Error, unable to load the .NET Host!");
		return EXIT_FAILURE;
	}

	WriteToPipe(pipeHandle, LOG_LEVEL_INFO, "Now loading the assembly.");

	// STEP 2: Initialize and start the .NET Core runtime
	std::wstring host_path_str = arguments->assembly_file_path;
	const std::wstring config_path = host_path_str.substr(0, host_path_str.length() - 4) + STR(".runtimeconfig.json");
	load_assembly_and_get_function_pointer = get_dotnet_load_assembly(config_path.c_str(), pipeHandle);

	assert(load_assembly_and_get_function_pointer != nullptr && "Failure: StartCoreCLR()");

	WriteToPipe(pipeHandle, LOG_LEVEL_INFO, "Done. Ready to execute.");

	// Release the pipe handle to allow further connections
	CloseHandle(pipeHandle);

	return 0;
}

void WriteToPipe(const HANDLE pipeHandle, const int loglevel, const std::string msg)
{
	const std::string message = std::format("{{ \"$type\": \"CoreHook.IPC.Messages.LogMessage\", \"Level\": {}, \"Source\": \"NativeHost\", \"Message\": \"{}\" }}\r\n", loglevel, msg);

	WriteFile(pipeHandle, message.c_str(), message.size(), nullptr, nullptr);
	FlushFileBuffers(pipeHandle);
}

// Create a native function delegate for a function inside a .NET assembly
SHARED_API int CreateAssemblyDelegate(const assembly_function_call* arguments, void** pfnDelegate)
{
	if (arguments == nullptr
		|| !check_arg_length(arguments->assembly_path, max_function_name_size)
		|| !check_arg_length(arguments->type_name_qualified, max_function_name_size)
		|| !check_arg_length(arguments->method_name, max_function_name_size))
		//|| !check_arg_length(arguments->delegate_type_name, max_function_name_size))
	{
		return 1;// coreload::StatusCode::InvalidArgFailure;
	}

	int rc = load_assembly_and_get_function_pointer(
		arguments->assembly_path,
		arguments->type_name_qualified,
		arguments->method_name,
		UNMANAGEDCALLERSONLY_METHOD,//	wcsnlen(arguments->delegate_type_name, 1) > 0 ? arguments->delegate_type_name : nullptr,
		nullptr /* reserved */,
		pfnDelegate);

	assert(rc == 0 && pfnDelegate != nullptr && "Failure: load_assembly_and_get_function_pointer()");

	return rc;
}

// Execute a function located in a .NET assembly by creating a native delegate
SHARED_API int ExecuteAssemblyFunction(const assembly_function_call* arguments)
{
	//while (!::IsDebuggerPresent())
	//	::Sleep(100); // to avoid 100% CPU load

	//DebugBreak();
	std::wstring pipename = arguments->pipename;
	HANDLE pipeHandle = CreateFile((STR("\\\\.\\pipe\\") + pipename).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);

	const std::wstring method = arguments->method_name;
	WriteToPipe(pipeHandle, LOG_LEVEL_INFO, std::format("Creating assembly function delegate for {}", "xxx"));

	load_plugin_fn* execute_delegate = nullptr;
	auto exit_code = CreateAssemblyDelegate(arguments, reinterpret_cast<PVOID*>(&execute_delegate));

	if (SUCCEEDED(exit_code))
	{
		WriteToPipe(pipeHandle, LOG_LEVEL_INFO, "Done, executing...");
		CloseHandle(pipeHandle);
		exit_code = execute_delegate(BSTR(arguments->payload));

		pipeHandle = CreateFile((STR("\\\\.\\pipe\\") + pipename).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);
		WriteToPipe(pipeHandle, LOG_LEVEL_INFO, std::format("Returned {}", exit_code));
		CloseHandle(pipeHandle);
	}
	else
	{
		WriteToPipe(pipeHandle, LOG_LEVEL_ERROR, std::format("Failed with error code {}", exit_code));
		CloseHandle(pipeHandle);
	}

	return exit_code;
}

// Shutdown the .NET Core runtime
SHARED_API int UnloadRuntime()
{
	// Not implemented
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
	default:
		break;
	}
	return TRUE;
}