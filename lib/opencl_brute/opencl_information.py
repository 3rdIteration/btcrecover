#!/usr/bin/python3
# -*- coding: utf-8 -*-
'''
    Original copyright:
    Copyright by B.Kerler 2017, PBKDF1_SHA1 and SHA256 PyOpenCl implementation, max 32 chars for password + salt
    MIT License
    Implementation was confirmed to work with Intel OpenCL on Intel(R) HD Graphics 520 and Intel(R) Core(TM) i5-6200U CPU
'''
'''
    Refactored out of 'opencl.py'
'''

try:
    import pyopencl as cl
except ImportError as _pyopencl_import_error:  # pragma: no cover - exercised when PyOpenCL missing
    cl = None
else:
    _pyopencl_import_error = None


def _require_pyopencl():
    if cl is None:
        raise ImportError(
            "pyopencl is required for querying OpenCL information but is not installed"
        ) from _pyopencl_import_error

class opencl_information:
    def __init__(self):
        pass

    def printplatforms(self):
        _require_pyopencl()
        for i,platformNum in enumerate(cl.get_platforms()):
            print('Platform %d - Name %s, Vendor %s' %(i,platformNum.name,platformNum.vendor))

    def printfullinfo(self):
        _require_pyopencl()
        print('\n' + '=' * 60 + '\nOpenCL Platforms and Devices')
        for i,platformNum in enumerate(cl.get_platforms()):
            print('=' * 60)
            print('Platform %d - Name: ' %i + platformNum.name)
            print('Platform %d - Vendor: ' %i + platformNum.vendor)
            print('Platform %d - Version: ' %i + platformNum.version)
            print('Platform %d - Profile: ' %i + platformNum.profile)

            for deviceIndex, device in enumerate(platformNum.get_devices()):
                print(' ' + '-' * 56)
                print('')
                print(' Device %d - Name: ' %deviceIndex + device.name)
                print(' Device %d - Type: ' %deviceIndex + cl.device_type.to_string(device.type))
                print(' Device %d - Max Clock Speed: {0} Mhz'.format(device.max_clock_frequency) %deviceIndex)
                print(' Device %d - Compute Units: {0}'.format(device.max_compute_units) %deviceIndex )
                print(' Device %d - Local Memory: {0:.0f} KB'.format(device.local_mem_size / 1024.0) %deviceIndex )
                print(' Device %d - Constant Memory: {0:.0f} KB'.format(device.max_constant_buffer_size / 1024.0) %deviceIndex )
                print(' Device %d - Global Memory: {0:.0f} GB'.format(device.global_mem_size / 1073741824.0) %deviceIndex )
                print(' Device %d - Max Buffer/Image Size: {0:.0f} MB'.format(device.max_mem_alloc_size / 1048576.0) %deviceIndex )
                print(' Device %d - Max Work Group Size: {0:.0f}'.format(device.max_work_group_size) %deviceIndex )
                print('\n')
