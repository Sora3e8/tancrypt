project(testkit VERSION 1.0.0 LANGUAGES CXX)

file(GLOB_RECURSE SRC_FILES src/*.cc src/*.cpp)
add_executable(${PROJECT_NAME} ${SRC_FILES})

# Basic memory bug
if(NOT ${CMAKE_SYSTEM_PROCESSOR} MATCHES "(arm|aarch64)")
  target_compile_options(${PROJECT_NAME} 
    PRIVATE
    $<$<CONFIG:Debug>: -fsanitize=address -fno-omit-frame-pointer>
  )
  target_link_options(${PROJECT_NAME}
    PRIVATE
    $<$<CONFIG:Debug>: -fsanitize=address>
  )
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE tancrypt)
target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/include")
add_test(NAME "Pkic Init" COMMAND ${PROJECT_NAME} --pkicInit)
add_test(NAME "Keypair generation" COMMAND ${PROJECT_NAME} --pairGen)
add_test(NAME "Keypair re-generation" COMMAND ${PROJECT_NAME} --pairRegen)
add_test(NAME "Keypair multi-generation" COMMAND ${PROJECT_NAME} --pairMultigen)
add_test(NAME "DER get privkey" COMMAND ${PROJECT_NAME} --getPrivDER)
add_test(NAME "DER get pubkey" COMMAND ${PROJECT_NAME} --getPubDER)
add_test(NAME "Get bitsize" COMMAND ${PROJECT_NAME} --getBits)
add_test(NAME "DER load privkey" COMMAND ${PROJECT_NAME} --loadPrivDER)
add_test(NAME "DER load pubkey" COMMAND ${PROJECT_NAME} --loadPubDER)
add_test(NAME "PEM priv get" COMMAND ${PROJECT_NAME} --getPrivPEM "${CMAKE_SOURCE_DIR}/data/test_data/priv.pem")
add_test(NAME "PEM pub get" COMMAND ${PROJECT_NAME} --getPubPEM "${CMAKE_SOURCE_DIR}/data/test_data/pub.pem")
add_test(NAME "PEM bundle get" COMMAND ${PROJECT_NAME} --getBundlePEM "${CMAKE_SOURCE_DIR}/data/test_data/bundle.pem")
add_test(NAME "PEM priv string load" COMMAND ${PROJECT_NAME} --loadPrivPEM)
add_test(NAME "PEM pub string load" COMMAND ${PROJECT_NAME} --loadPubPEM)
add_test(NAME "PEM bundle string load" COMMAND ${PROJECT_NAME} --loadBundlePEM)
add_test(NAME "PEM import privkey" COMMAND ${PROJECT_NAME} --importPrivPEM "${CMAKE_SOURCE_DIR}/data/test_data/priv.pem")
add_test(NAME "PEM import pubkey" COMMAND ${PROJECT_NAME} --importPubPEM "${CMAKE_SOURCE_DIR}/data/test_data/pub.pem")
add_test(NAME "PEM import bundle" COMMAND ${PROJECT_NAME} --importBundlePEM "${CMAKE_SOURCE_DIR}/data/test_data/bundle.pem")
add_test(NAME "PEM priv export" COMMAND ${PROJECT_NAME} --exportPrivPEM)
add_test(NAME "PEM pub export" COMMAND ${PROJECT_NAME} --exportPubPEM)
add_test(NAME "PEM bundle export" COMMAND ${PROJECT_NAME} --exportBundlePEM)
add_test(NAME "Encrypt" COMMAND ${PROJECT_NAME} --encrypt)
add_test(NAME "Decrypt" COMMAND ${PROJECT_NAME} --decrypt)
add_test(NAME "Hash" COMMAND ${PROJECT_NAME} --hash)
add_test(NAME "Sign" COMMAND ${PROJECT_NAME} --sign)
add_test(NAME "Verify" COMMAND ${PROJECT_NAME} --verify)
add_test(NAME "AES key constructor v1" COMMAND ${PROJECT_NAME} --aesKeyInit1)
add_test(NAME "AES key constructor v2" COMMAND ${PROJECT_NAME} --aesKeyInit2)
add_test(NAME "AES random key" COMMAND ${PROJECT_NAME} --aesRandomKey)
add_test(NAME "AES encrypt v1" COMMAND ${PROJECT_NAME} --aesEncryptV1)
add_test(NAME "AES encrypt v2" COMMAND ${PROJECT_NAME} --aesEncryptV2)
add_test(NAME "AES encrypt random key" COMMAND ${PROJECT_NAME} --aesEncryptwRandomKey)
add_test(NAME "AES decrypt v1" COMMAND ${PROJECT_NAME} --aesDecryptV1)
add_test(NAME "AES decrypt v2" COMMAND ${PROJECT_NAME} --aesDecryptV2)
add_test(NAME "AES get nonce" COMMAND ${PROJECT_NAME} --getNonce)

if(DO_TEST)
  add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_CTEST_COMMAND} -C Debug --output-on-failure)
endif()

