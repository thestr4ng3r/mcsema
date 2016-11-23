
#include <boost/python.hpp>
#include "llvm_lifter.h"

using namespace boost::python;

const char *test();


void init_mcsema();
int bin_descend(std::string in_filename, std::string out_filename);



BOOST_PYTHON_MODULE(mcsema)
{
	def("test", test);

	def("init_mcsema", init_mcsema);
	def("bin_descend", bin_descend);

	class_<LLVMLifter>("LLVMLifter", init<std::string>())
			.def("test", &LLVMLifter::Test);
}
