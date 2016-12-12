
#include <boost/python.hpp>
#include "llvm_lifter.h"

using namespace boost::python;


BOOST_PYTHON_MODULE(mcsema)
{
	def("initialize", InitializeLLVMLifter);

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


	class_<LLVMLifter>("LLVMLifter", init<>())
			.def("bin_descend", &LLVMLifter::BinDescend)
			.def("cfg_to_bc", &LLVMLifter::CFGToBC)
			.add_property("arch", &LLVMLifter::GetSystemArch, &LLVMLifter::SetSystemArch)
			.add_property("func_maps", &LLVMLifter::GetFunctionMaps, &LLVMLifter::SetFunctionMaps)
			.add_property("entry_symbols", &LLVMLifter::GetEntrySymbols, &LLVMLifter::SetEntrySymbols)
			.add_property("entry_points", &LLVMLifter::GetEntryPoints, &LLVMLifter::GetEntryPoints)
			.add_property("drivers", &LLVMLifter::GetDrivers, &LLVMLifter::SetDrivers)
			.add_property("bitcode", &LLVMLifter::GetBitcode);
}
