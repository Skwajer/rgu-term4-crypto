cmake_minimum_required(VERSION 3.15)  # лучше использовать 3.15 вместо 4.0

project(term4-crypto LANGUAGES CXX)

include(FetchContent)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_testing()

# Подключаем Google Test
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Включаем директории
include_directories(src)

# ==== ОСНОВНАЯ ПРОГРАММА ====
# Список всех исходных файлов
set(SOURCES
    src/core/CryptoProcessor.cpp
    src/core/DESCipher.cpp
    src/core/FeistelCipher.cpp
    src/bits/Pbox_permutation.cpp
    src/bits/Sbox_substitution.cpp
    src/core/FeistelNetwork.cpp
    main.cpp
    src/core/des_tables.cpp

)

# Создаем исполняемый файл
add_executable(crypto_demo ${SOURCES})

# Явно указываем, где искать заголовочные файлы
target_include_directories(crypto_demo PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bits
)

# Если используете какие-то дополнительные библиотеки
# target_link_libraries(crypto_demo PRIVATE ...)

# ==== ТЕСТЫ ====
# add_subdirectory(tests)