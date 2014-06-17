CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

include(CMakeCommon.cmake)

#整个解决方案的名称
PROJECT(testsctp)

#配置DEBUG选项
SetDebug()

#设置输出路径
SetOutputCfg()

#添加头文件收缩路径
AddHeaderDirs("")

#设置依赖库
UNSET(LIB_LIST)
SET(LIB_LIST
)
#设置与平台相关的依赖库
IF(MSVC)
SET(LIBS_LIST 
${LIBS_LIST}
ws2_32)
ELSE()
SET(LIBS_LIST
${LIBS_LIST}
pthread)
ENDIF()

#添加执行程序工程
ADD_EXECUTABLE(testclient ${CMAKE_CURRENT_LIST_DIR}/testclient.cc)
#添加执行程序依赖
TARGET_LINK_LIBRARIES(testclient ${LIBS_LIST})

ADD_SUBDIRECTORY(./usrsctplib)
