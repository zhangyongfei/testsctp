FUNCTION(AddLibDirs PATHLIST)
    LINK_DIRECTORIES(${PATHLIST})
ENDFUNCTION(AddLibDirs)

FUNCTION(AddLibDirsWin32 DEFS)
IF(WIN32)
    AddLibDirs(${DEFS})
ENDIF()
ENDFUNCTION(AddLibDirsWin32)

FUNCTION(AddLibDirsLinux DEFS)
IF(UNIX AND NOT APPLE)
    AddLibDirs(${DEFS})
ENDIF()
ENDFUNCTION(AddLibDirsLinux)

FUNCTION(AddLibDirsOsx DEFS)
IF(APPLE)
    AddLibDirs(${DEFS})
ENDIF()
ENDFUNCTION(AddLibDirsOsx)

FUNCTION(AddLibDirsAndroid DEFS)
IF(UNIX AND NOT APPLE AND NOT CYGWIN)
    AddLibDirs(${DEFS})
ENDIF()
ENDFUNCTION(AddLibDirsAndroid)

#------------------------------------------------------------------

FUNCTION(AddLibs LIBSLIST LIB)
    SET(${LIBSLIST} ${LIB} PARENT_SCOPE)
ENDFUNCTION(AddLibs)

FUNCTION(AddLibsWin32 LIBSLIST LIB)
IF(WIN32)
    SET(${LIBSLIST} ${LIB} PARENT_SCOPE)
ENDIF()
ENDFUNCTION(AddLibsWin32)

FUNCTION(AddLibsLinux LIBSLIST LIB)
IF(UNIX AND NOT APPLE)
    SET(${LIBSLIST} ${LIB} PARENT_SCOPE)
ENDIF()
ENDFUNCTION(AddLibsLinux)

FUNCTION(AddLibsApple LIBSLIST LIB)
IF(APPLE)
    SET(${LIBSLIST} ${LIB} PARENT_SCOPE)
ENDIF()
ENDFUNCTION(AddLibsApple)

FUNCTION(AddLibsAndroid LIBSLIST LIB)
IF(UNIX AND NOT APPLE AND NOT CYGWIN)
    SET(${LIBSLIST} ${LIB} PARENT_SCOPE)
ENDIF()
ENDFUNCTION(AddLibsAndroid)