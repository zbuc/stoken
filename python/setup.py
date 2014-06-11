from distutils.core import setup, Extension
 
module1 = Extension('stoken', sources = ['stokenmodule.c'], include_dirs = ['/usr/local/include'], libraries = ['stoken'], library_dirs = ['/usr/local/lib'])
 
setup (name = 'PackageName',
        version = '1.0',
        description = 'This is a demo package',
        ext_modules = [module1])

