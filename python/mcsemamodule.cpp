
#include <boost/python.hpp>

#include "lifter.h"

using namespace boost::python;


BOOST_PYTHON_MODULE(mcsema)
{
	//class_<NativeModule, boost::shared_ptr<NativeModule>>("NativeModule", no_init);

	/*enum_<ExternalCodeRef::CallingConvention>("calling_convention")
			.value("caller_cleanup", ExternalCodeRef::CallerCleanup)
			.value("callee_cleanup", ExternalCodeRef::CalleeCleanup)
			.value("fast_call", ExternalCodeRef::FastCall)
			.value("x86_64_sysv", ExternalCodeRef::X86_64_SysV)
			.value("x86_64_win64", ExternalCodeRef::X86_64_Win64);*/

	class_<Lifter>("Lifter", init<std::string, std::string, object>())
			.def("execute", &Lifter::Execute)
			.def("execute", &Lifter::ExecuteAndSave)
			//.add_property("native_module", &Lifter::GetNativeModule, &Lifter::SetNativeModule)
			.add_property("entry_points", &Lifter::GetEntryPoints, &Lifter::SetEntryPoints)
			.add_property("ignore_unsuppported_insts", &Lifter::GetIgnoreUnsupportedInsts, &Lifter::SetIgnoreUnsupportedInsts)
			.add_property("add_breakpoints", &Lifter::GetAddBreakpoints, &Lifter::SetAddBreakpoints)
			.add_property("add_tracer", &Lifter::GetAddTracer, &Lifter::SetAddTracer)
			.add_property("bitcode", &Lifter::GetBitcode);
}
