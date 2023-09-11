cmake_minimum_required(VERSION 3.25)
project(sealing)

set(CMAKE_CXX_STANDARD 17)


link_directories(/usr/local/lib/)
link_directories(/usr/lib64)

add_executable(sealing main.cpp structures.h testSealing.cpp testSealing.h TPM.cpp TPM.h)

target_include_directories(sealing PUBLIC /usr/local/include/tss2/)

target_link_libraries(sealing tss2-tcti-tabrmd tss2-esys tss2-mu crypto tss2-tcti-device tss2-sys)
