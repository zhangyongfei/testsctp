cmake_minimum_required(VERSION 2.8)

#添加用户宏定义
AddDefs("-DSCTP_DEBUG -DSCTP_SIMPLE_ALLOCATOR -DSCTP_PROCESS_LEVEL_LOCKS -D__Userspace__ -DINET -DINET6 -D_LIB")
AddDefsWin32("-D__Userspace_os_Windows")
AddDefsLinux("-D__Userspace_os_Linux")

#添加源文件路径
SET(SOURCE_LIST)
AddSrcDir(SOURCE_LIST ${CMAKE_CURRENT_LIST_DIR}/netinet)
AddSrcDir(SOURCE_LIST ${CMAKE_CURRENT_LIST_DIR}/netinet6)
AddSrcDir(SOURCE_LIST ${CMAKE_CURRENT_LIST_DIR})

StaticLib(usrsctplib SOURCE_LIST LIB_LIST)


