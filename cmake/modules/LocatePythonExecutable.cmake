# Try to find Python and set PYTHON_EXECUTABLE on Windows prior to
# calling FindPythonInterp in order to keep us from using Cygwin's Python.
# http://public.kitware.com/Bug/view.php?id=13818

if( NOT PYTHON_EXECUTABLE AND ( WIN32 OR CYGWIN ) )
    foreach(_major_version 3 2)
        foreach(_minor_version "" .7 .6 .5 .4 .3 .2 .1)
            if (PYTHON_EXECUTABLE)
                break()
            endif()
            find_program(PYTHON_EXECUTABLE
                NAMES
                    python.exe
                    python${_major_version}${_minor_version}
                PATHS
                    [HKEY_LOCAL_MACHINE\\SOFTWARE\\Python\\PythonCore\\${_major_version}${_minor_version}\\InstallPath]
                    [HKEY_LOCAL_MACHINE\\SOFTWARE\\Python\\PythonCore\\${_major_version}${_minor_version}-32\\InstallPath]
                    [HKEY_LOCAL_MACHINE\\SOFTWARE\\Python\\PythonCore\\${_major_version}${_minor_version}-64\\InstallPath]
            )
        endforeach()
    endforeach()
endif()
