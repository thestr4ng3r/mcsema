
#ifndef _MCSEMA_PYTHON_BIN_DESCEND_H
#define _MCSEMA_PYTHON_BIN_DESCEND_H

#include <string>
#include <vector>

#include <boost/python.hpp>

#include "cfg_recover.h"

class BinDescend
{
	private:
		const llvm::Target *x86_target;
		llvm::Triple *triple;

		std::string system_arch;

		boost::python::list entry_symbols;
		boost::python::list entry_points;

		boost::python::list func_maps;

		bool ignore_native_entry_points = true;
		bool debug_mode = false;

		NativeModulePtr module;

		NativeModulePtr MakeNativeModule(ExecutableContainer *exc, ExternalFunctionMap &funcs);

	public:
		BinDescend();

		int Execute(std::string in_filename);


		NativeModulePtr GetNativeModule() const					{ return module; }

		std::string GetTargetTriple() const 					{ return triple->getTriple(); }

		std::string GetSystemArch() const						{ return system_arch; }
		void SetSystemArch(std::string system_arch);

		boost::python::list GetFunctionMaps() const 			{ return func_maps; }
		void SetFunctionMaps(boost::python::list func_maps) 	{ this->func_maps = func_maps; }

		boost::python::list GetEntrySymbols() const 			{ return entry_symbols; }
		void SetEntrySymbols(boost::python::list entry_symbols)	{ this->entry_symbols = entry_symbols; }

		boost::python::list GetEntryPoints() const 				{ return entry_points; }
		void SetEntryPoints(boost::python::list entry_points)	{ this->entry_points = entry_points; }

		bool GetIgnoreNativeEntryPoints() const 				{ return ignore_native_entry_points; }
		void SetIgnoreNativeEntryPoints(bool ignore)			{ this->ignore_native_entry_points = ignore; }

		bool GetDebugMode() const 								{ return debug_mode; }
		void SetDebugMode(bool debug_mode)						{ this->debug_mode = debug_mode; }
};


#endif
