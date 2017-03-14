
#include <boost/python.hpp>

#include "mcsema_init.h"
#include "cfg_to_llvm.h"

using namespace boost::python;


BOOST_PYTHON_MODULE(mcsema)
{
	def("initialize", InitializeMCSema);

	//class_<NativeModule, boost::shared_ptr<NativeModule>>("NativeModule", no_init);

	enum_<ExternalCodeRef::CallingConvention>("calling_convention")
			.value("caller_cleanup", ExternalCodeRef::CallerCleanup)
			.value("callee_cleanup", ExternalCodeRef::CalleeCleanup)
			.value("fast_call", ExternalCodeRef::FastCall)
			.value("x86_64_sysv", ExternalCodeRef::X86_64_SysV)
			.value("x86_64_win64", ExternalCodeRef::X86_64_Win64);

	class_<CFGToLLVM>("CFGToLLVM", init<object>())
			.def("execute", &CFGToLLVM::Execute)
			.def("execute", &CFGToLLVM::ExecuteAndSave)
			//.add_property("native_module", &CFGToLLVM::GetNativeModule, &CFGToLLVM::SetNativeModule)
			//.add_property("target_triple", &CFGToLLVM::GetTargetTriple, &CFGToLLVM::SetTargetTriple)
			.add_property("entry_points", &CFGToLLVM::GetEntryPoints, &CFGToLLVM::SetEntryPoints)
			.add_property("bitcode", &CFGToLLVM::GetBitcode);
}
