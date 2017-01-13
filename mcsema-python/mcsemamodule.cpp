
#include <boost/python.hpp>

#include "mcsema_init.h"
#include "bin_descend.h"
#include "cfg_to_llvm.h"

using namespace boost::python;


BOOST_PYTHON_MODULE(mcsema)
{
	def("initialize", InitializeMCSema);


	class_<NativeModule, boost::shared_ptr<NativeModule>>("NativeModule", no_init);

	class_<BinDescend>("BinDescend", init<std::string>())
			.def("execute", &BinDescend::Execute)
			.def("execute", &BinDescend::ExecuteAndSave)
			.add_property("arch", &BinDescend::GetSystemArch, &BinDescend::SetSystemArch)
			.add_property("func_maps", &BinDescend::GetFunctionMaps, &BinDescend::SetFunctionMaps)
			.add_property("entry_symbols", &BinDescend::GetEntrySymbols, &BinDescend::SetEntrySymbols)
			.add_property("entry_points", &BinDescend::GetEntryPoints, &BinDescend::SetEntryPoints)
			.add_property("ignore_native_entry_points", &BinDescend::GetIgnoreNativeEntryPoints, &BinDescend::SetIgnoreNativeEntryPoints)
			.add_property("debug_mode", &BinDescend::GetDebugMode, &BinDescend::SetDebugMode)
			.add_property("native_module", &BinDescend::GetNativeModule)
			.add_property("target_triple", &BinDescend::GetTargetTriple);



	enum_<ExternalCodeRef::CallingConvention>("calling_convention")
			.value("caller_cleanup", ExternalCodeRef::CallerCleanup)
			.value("callee_cleanup", ExternalCodeRef::CalleeCleanup)
			.value("fast_call", ExternalCodeRef::FastCall)
			.value("x86_64_sysv", ExternalCodeRef::X86_64_SysV)
			.value("x86_64_win64", ExternalCodeRef::X86_64_Win64);

	class_<DriverEntry>("DriverEntry")
			.def_readwrite("is_raw", &DriverEntry::is_raw)
			.def_readwrite("returns", &DriverEntry::returns)
			.def_readwrite("argc", &DriverEntry::argc)
			.def_readwrite("name", &DriverEntry::name)
			.def_readwrite("sym", &DriverEntry::sym)
			.def_readwrite("sign", &DriverEntry::sign)
			.def_readwrite("ep", &DriverEntry::ep)
			.def_readwrite("cconv", &DriverEntry::cconv);

	class_<CFGToLLVM>("CFGToLLVM", init<std::string, object>())
			.def("execute", &CFGToLLVM::Execute)
			.def("execute", &CFGToLLVM::ExecuteAndSave)
			.add_property("native_module", &CFGToLLVM::GetNativeModule, &CFGToLLVM::SetNativeModule)
			.add_property("target_triple", &CFGToLLVM::GetTargetTriple, &CFGToLLVM::SetTargetTriple)
			.add_property("drivers", &CFGToLLVM::GetDrivers, &CFGToLLVM::SetDrivers)
			.add_property("bitcode", &CFGToLLVM::GetBitcode);
}
