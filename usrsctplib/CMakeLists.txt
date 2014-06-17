cmake_minimum_required(VERSION 2.8)

#添加用户宏定义
AddDefines("-DSCTP_DEBUG -DSCTP_SIMPLE_ALLOCATOR -DSCTP_PROCESS_LEVEL_LOCKS -D__Userspace__ -DINET -DINET6 -D_LIB")
if(MSVC)
AddDefines("-D__Userspace_os_Windows")
else()
AddDefines("-D__Userspace_os_Linux")
endif()



#添加源文件路径
SET(SOURCE_LIST)
AddSrcDirs(${CMAKE_CURRENT_LIST_DIR}/netinet SOURCE_LIST)
AddSrcDirs(${CMAKE_CURRENT_LIST_DIR}/netinet6 SOURCE_LIST)
AddSrcDirs(${CMAKE_CURRENT_LIST_DIR}/ SOURCE_LIST)

#设置头文件
SET(HEADER_LIST
${CMAKE_CURRENT_LIST_DIR}/netinet/*.h
${CMAKE_CURRENT_LIST_DIR}/netinet6/*.h
${CMAKE_CURRENT_LIST_DIR}/*.h
)

AddHeaderDirs(
${CMAKE_CURRENT_LIST_DIR} 
${CMAKE_CURRENT_LIST_DIR}/netinet 
${CMAKE_CURRENT_LIST_DIR}/netinet6)

#设置所有文件列表
SET(ALL_FILES)
FILE(GLOB_RECURSE ALL_FILES ${HEADER_LIST} ${SOURCE_LIST})

ShareLib(usrsctplib ${ALL_FILES} ${LIBS_LIST})


