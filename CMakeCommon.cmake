MACRO(SOURCE_GROUP_BY_DIR SOURCE_FILES)
    IF(MSVC)
        SET(SGBD_CUR_DIR ${CMAKE_CURRENT_SOURCE_DIR})
        FOREACH(SGBD_FILE ${${SOURCE_FILES}})
            STRING(REGEX REPLACE ${SGBD_CUR_DIR}/\(.*\) \\1 SGBD_FPATH ${SGBD_FILE})
            STRING(REGEX REPLACE "\(.*\)/.*" \\1 SGBD_GROUP_NAME ${SGBD_FPATH})
			message("123---${SGBD_FPATH}")
            STRING(COMPARE EQUAL ${SGBD_FPATH} ${SGBD_GROUP_NAME} SGBD_NOGROUP)
            STRING(REPLACE "/" "\\" SGBD_GROUP_NAME ${SGBD_GROUP_NAME})
            IF(SGBD_NOGROUP)
                SET(SGBD_GROUP_NAME "\\")
            ENDIF(SGBD_NOGROUP)
            SOURCE_GROUP(${SGBD_GROUP_NAME} FILES ${SGBD_FILE})
        ENDFOREACH(SGBD_FILE)
    ENDIF(MSVC)
ENDMACRO(SOURCE_GROUP_BY_DIR)

FUNCTION(EnableUserFolders)
	IF(MSVC) 
		SET_PROPERTY(GLOBAL PROPERTY USE_FOLDERS ON)
	ENDIF()	
ENDFUNCTION()

FUNCTION(SetDebug)
	SET(CMAKE_BUILD_TYPE DEBUG)
	IF(MSVC) 
		SET(CMAKE_C_FLAGS "-DWIN32 -D_DEBUG -DDEBUG")
		SET(CMAKE_CXX_FLAGS "-DWIN32 -D_DEBUG -DDEBUG /EHSC")
	ELSE()
		SET(CMAKE_C_FLAGS "-O0 -GGDB -D_DEBUG -DDEBUG -DPOSIX -DLINUX")
		SET(CMAKE_CXX_FLAGS "-O0 -GGDB -D_DEBUG -DDEBUG -DPOSIX -DLINUX")
		SET(CMAKE_C_FLAGS_DEBUG "-O0 -GGDB")
		SET(CMAKE_C_FLAGS_RELEASE "-O0 -GGDB")
		SET(CMAKE_CXX_FLAGS_DEBUG "-O0 -GGDB")
		SET(CMAKE_CXX_FLAGS_RELEASE "-O0 -GGDB")
	ENDIF()
ENDFUNCTION()

FUNCTION(SetOutputCfg)
    IF(MSVC)
	    SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CACHEFILE_DIR})
		SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CACHEFILE_DIR})
		SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CACHEFILE_DIR})
	ELSE()
		SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CACHEFILE_DIR}/lib)
		SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CACHEFILE_DIR}/lib)
		SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CACHEFILE_DIR}/bin)
	ENDIF()
ENDFUNCTION()

FUNCTION(AddDefines DEFS)
    ADD_DEFINITIONS(${DEFS})
ENDFUNCTION()

FUNCTION(AddHeaderDirs PATHLIST)
    INCLUDE_DIRECTORIES(${PATHLIST} ${CMAKE_CURRENT_LIST_DIR})
ENDFUNCTION()

FUNCTION(AddLibDirs PATHLIST)
    LINK_DIRECTORIES(${PATHLIST} ${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})
ENDFUNCTION()

FUNCTION(AddSrcDirs PATHLIST SRCLIST)
    SET(TMPSRCLIST)
    AUX_SOURCE_DIRECTORY(${PATHLIST} TMPSRCLIST)
	SET(${SRCLIST} ${SRCLIST} ${TMPSRCLIST} PARENT_SCOPE)
ENDFUNCTION()

FUNCTION(AddSrcFile FILELIST SRCLIST)
	SET(${SRCLIST} ${SRCLIST} ${FILELIST} ${TMPSRCLIST} PARENT_SCOPE)
ENDFUNCTION()

FUNCTION(AddSubPrj PRJPATH)
	ADD_SUBDIRECTORY(${PRJPATH})
ENDFUNCTION()

FUNCTION(AppPrj PRJNAME SRCLIST LIBLIST)
    ADD_EXECUTABLE(${PRJNAME} ${SRCLIST})
	TARGET_LINK_LIBRARIES(${PRJNAME} ${LIBLIST})
ENDFUNCTION()

FUNCTION(StaticLib PRJNAME SRCLIST)
    ADD_LIBRARY(${PRJNAME} STATIC ${SRCLIST})
ENDFUNCTION()

FUNCTION(ShareLib PRJNAME SRCLIST LIBLIST)
    ADD_LIBRARY(${PRJNAME} SHARED ${SRCLIST})
	TARGET_LINK_LIBRARIES(${PRJNAME} ${LIBLIST})
ENDFUNCTION()
