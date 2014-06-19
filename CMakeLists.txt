CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_LIST_DIR}/CMakeUtility)
include(CMakeUtility)

Solution(testsctp ON)

#设置依赖库
SET(LIB_LIST)
AddLibsWin32(LIB_LIST
usrsctplib
ws2_32)
AddLibsLinux(LIB_LIST
usrsctplib
pthread)

AddDefs("-DSCTP_DEBUG")

AddHDir(${CMAKE_CURRENT_LIST_DIR}/usrsctplib)

SET(SOURCE_LIST
${CMAKE_CURRENT_LIST_DIR}/testclient.cc)

AppPrj(testclient 
SOURCE_LIST
LIB_LIST)

SET(SOURCE_LIST
${CMAKE_CURRENT_LIST_DIR}/testserver.cc)

AppPrj(testserver
SOURCE_LIST
LIB_LIST)

AddSubPrj(./usrsctplib)

