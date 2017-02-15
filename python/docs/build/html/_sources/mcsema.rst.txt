
.. _mcsema:

mcsema.mcsema -- McSema's internal functionality
================================================

.. module:: mcsema.msema
   :synopsis: Contains all exposed functionality from McSema's C++ code.


.. class:: NativeModule

   A module in native code in the form of a control flow graph.


.. class:: BinDescend(input_file)

   Exposes the functionality of bin_descend. *input_file* specifies the
   path to the binary.

   .. attribute:: arch

      Architecture of the binary. Set to "x86" or "x86-64".

   .. attribute:: func_maps

      List of paths to txt files containing information about external functions.

   .. attribute:: entry_symbols

      List of entry points in the form of symbols.

   .. attribute:: entry_points

      List of entry points in the form of addresses.

   .. attribute:: ignore_native_entry_points

   .. attribute:: debug_mode

   .. attribute:: native_module

      *readonly*. Contains the :class:`NativeModule` after a successful CFG recovery.

   .. attribute:: target_triple

      *readonly*. Contains the target triple which can be passed to :class:`CFGToLLVM`.

   .. method:: execute()

      Recover CFG. Returns True on success and False otherwise.

   .. method:: execute(cfg_file)

      Like *execute()*, but additionally save the CFG to *cfg_file*
      in McSema's Protobuf format.


.. class:: CFGToLLVM(target_triple, cfg)

   Exposes the functionality of cfg_to_bc.
   *target_triple* can be passed from ::class:`BinDescend`.
   *cfg* can be either a path to a CFG file as a string or an instance of :class:`NativeModule`.

   .. attribute:: native_module

      :class:`NativeModule` used as the input to lift.

   .. attribute:: target_triple

   .. attribute:: entry_points

      List of names for entry points.

   .. attribute:: bitcode

      *readonly*. Contains lifted bitcode after a successful translation.

   .. method:: execute()

      Translate to LLVM. Resulting bitcode can be read from *bitcode*.

   .. method:: execute(bc_file)

      Like *execute()*, but additionally save the bitcode to *bc_file*.
