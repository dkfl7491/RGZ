cmake_minimum_required(VERSION 3.10)
project(EncryptionRGR)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Путь к общим заголовкам
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Подключаем подпроекты (каждая библиотека собирается отдельно)
add_subdirectory(algorithms/autokeyCipher)
add_subdirectory(algorithms/vernamCipher)
add_subdirectory(algorithms/affineCipher)
# add_subdirectory(algorithms/другие...)

# Главное приложение (EXE)
add_executable(EncryptionRGR main.cpp)

target_include_directories(EncryptionRGR PRIVATE ${INCLUDE_DIR})

if(MSVC)
    target_compile_options(EncryptionRGR PRIVATE /source-charset:utf-8 /execution-charset:windows-1251)
else()
    target_compile_options(EncryptionRGR PRIVATE -finput-charset=UTF-8 -fexec-charset=UTF-8)
endif()

# Для Linux: добавляем библиотеку dl (для dlopen/dlsym)
if(UNIX AND NOT WIN32)
    target_link_libraries(EncryptionRGR dl)
endif()

# ВАЖНО: Указываем, что EXE зависит от DLL (чтобы DLL собрались первыми)
if(WIN32)
    add_dependencies(EncryptionRGR autokeyCipher feistelCipher caesarCipher lcgCipher teaCipher chacha20 vernamCipher affineCipher) 
endif()


message(STATUS "Project: ${PROJECT_NAME}")
message(STATUS "  Executable: ${PROJECT_NAME}")
message(STATUS "  Libraries: autokeyCipher,  vernamCipher, affineCipher")
