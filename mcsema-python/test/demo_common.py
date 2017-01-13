
from sys import argv
from subprocess import call
import os

import mcsema
import cfg_ida


def begin():
	clean_files = "*.o *.ll *.bc *.idb *.cfg demo_driver"

	if len(argv) > 1:
		if argv[1] == "clean":
			call("rm -fv " + clean_files, shell=True)
			quit()

	call("rm -f " + clean_files, shell=True)


def cfg_generator(input_file):
	ida_exec = os.getenv("IDA_EXEC")
	if ida_exec:
		print("Using IDA \"" + ida_exec + "\" for CFG generation.")
		return cfg_ida.IDACFGGenerator(ida_exec, "../../../mc-sema/bin_descend/get_cfg.py", input_file)
	else:
		print("Using bin_descend for CFG generation.")
		return mcsema.BinDescend(input_file)
