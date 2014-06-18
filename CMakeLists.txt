CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_LIST_DIR}/CMakeUtility)
include(CMakeUtility)

Solution(testsctp OFF)

#设置依赖库
SET(LIB_LIST)
AddLibsWin32(LIB_LIST
ws2_32)
AddLibsLinux(LIB_LIST
ws2_32)

AppPrj(testclient 
${CMAKE_CURRENT_LIST_DIR}/testclient.cc
${LIB_LIST})

AddSubPrj(./usrsctplib)

