
#include <boost/python.hpp>

using namespace boost::python;

const char *test();

BOOST_PYTHON_MODULE(mcsema)
{
	def("test", test);
}