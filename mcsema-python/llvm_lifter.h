//
// Created by florian on 23.11.16.
//

#ifndef MC_SEMA_LLVM_LIFTER_H
#define MC_SEMA_LLVM_LIFTER_H

#include <string>
#include <vector>

#include <boost/python.hpp>

#include "bin_descend/cfg_recover.h"

class LLVMLifter
{
	private:
		std::string system_arch;

		boost::python::list entry_symbols;
		boost::python::list entry_points;

		boost::python::list func_maps;

		bool ignore_native_entry_points = true;
		bool debug_mode = false;

		NativeModulePtr MakeNativeModule(ExecutableContainer *exc, ExternalFunctionMap &funcs);

	public:
		LLVMLifter();

		int BinDescend(std::string in_filename, std::string out_filename);

	public:
		std::string GetSystemArch() const						{ return system_arch; }
		void SetSystemArch(const std::string system_arch) 		{ this->system_arch = system_arch; }

		boost::python::list GetFunctionMaps() const 			{ return func_maps; }
		void SetFunctionMaps(boost::python::list func_maps) 	{ this->func_maps = func_maps; }

		boost::python::list GetEntrySymbols() const 			{ return entry_symbols; }
		void SetEntrySymbols(boost::python::list entry_symbols)	{ this->entry_symbols = entry_symbols; }

		boost::python::list GetEntryPoints() const 				{ return entry_points; }
		void SetEntryPoints(boost::python::list entry_points)	{ this->entry_points = entry_points; }
};

#endif //MC_SEMA_LLVM_LIFTER_H
