
#include <boost/python.hpp>
#include "llvm_lifter.h"

using namespace boost::python;


BOOST_PYTHON_MODULE(mcsema)
{
	def("initialize", InitializeLLVMLifter);

	class_<LLVMLifter>("LLVMLifter", init<>())
			.def("bin_descend", &LLVMLifter::BinDescend)
			.def("cfg_to_bc", &LLVMLifter::CFGToBC)
			.add_property("arch", &LLVMLifter::GetSystemArch, &LLVMLifter::SetSystemArch)
			.add_property("func_maps", &LLVMLifter::GetFunctionMaps, &LLVMLifter::SetFunctionMaps)
			.add_property("entry_symbols", &LLVMLifter::GetEntrySymbols, &LLVMLifter::SetEntrySymbols)
			.add_property("entry_points", &LLVMLifter::GetEntryPoints, &LLVMLifter::GetEntryPoints)
			.add_property("drivers", &LLVMLifter::GetDriversArgs, &LLVMLifter::SetDriversArgs);
}
