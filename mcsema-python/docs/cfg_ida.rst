
.. _cfg_ida:

mcsema.cfg_ida -- IDA Pro get_cfg.py wrapper
============================================

.. module:: mcsema.cfg_ida


.. class:: IDACFGGenerator(ida_exec, get_cfg_py, input_file)

   Wrapper to conveniently run IDA Pro with get_cfg.py script.
   *ida_exec* specifies the path to idaq or idaq64 for 64Bit binaries.
   *get_cfg_py* specifies the path to get_cfg.py.
   *input_file* specifies the path to the binary.

   .. attribute:: func_maps

      List of paths to txt files containing information about external functions.

   .. attribute:: entry_symbols

      List of entry points.

   .. attribute:: debug_mode

   .. attribute:: batch_mode

   .. method:: execute(cfg_file)

      Executes IDA Pro to recover CFG and save to *cfg_file*.
