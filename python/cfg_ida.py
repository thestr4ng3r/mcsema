
import sys
import subprocess
from os.path import join, dirname, splitext
import os


class IDACFGGenerator():
	def __init__(self, ida_exec, get_cfg_py, input_file):
		self._ida_exec = ida_exec
		self._get_cfg_py = get_cfg_py
		self._input_file = input_file

		self.entry_symbols = []

		self.func_maps = []

		self.debug_mode = False
		self.batch_mode = True

	def execute(self, output_file=None):
		new_args = ['--batch']

		if self.debug_mode:
			new_args.append('--debug')


		for entry_symbol in self.entry_symbols:
			new_args.extend(['--entry-symbol', entry_symbol])

		for func_map in self.func_maps:
			new_args.extend(['--std-defs', func_map])

		if not output_file:
			in_fname, in_ext = splitext(self._input_file)
			output_file = in_fname + ".cfg"

		new_args.extend(['--output', output_file])

		internal_args = [self._get_cfg_py]
		internal_args.extend(new_args)

		argstr = " ".join(internal_args)

		external_args = [self._ida_exec]

		if self.batch_mode:
			external_args.append("-B")

		external_args.extend(["-S"+argstr, self._input_file])

		sys.stdout.write("Executing: {0}\n".format(str(external_args)))

		#env = os.environ.copy()
		#env["PYTHONPATH"] = ""
		#subprocess.Popen(external_args, env=env)

		subprocess.call(external_args)
