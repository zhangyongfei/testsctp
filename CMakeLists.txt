CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_LIST_DIR}/CMakeUtility)
include(CMakeUtility)

Solution(testsctp OFF)

#设置依赖库
SET(LIB_LIST)
AddLibsWin32(LIB_LIST
ws2_32)
AddLibsLinux(LIB_LIST
pthread)

AddSrc(SOURCE_LIST
${CMAKE_CURRENT_LIST_DIR}/testclient.cc)

AppPrj(testclient 
SOURCE_LIST
LIB_LIST)

AddSubPrj(./usrsctplib)

