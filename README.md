# XORCryptorLib

Encrypt and decrypt using XOR bitwise operation

[About algorithm](About.md)

Checkout it's Rust implementation [here](https://github.com/shank03/XORCryptorRust)

### Adding to CMake project
```shell
$ cd <project_folder>
$ git clone https://github.com/shank03/XORCryptorLib -b main XRC
```

Go to `CMakeLists.txt` and paste this:
```cmake
...
# after add_executable

add_subdirectory(XRC)
target_include_directories(${PROJECT_NAME} PUBLIC XRC)
target_link_directories(${PROJECT_NAME} PRIVATE XRC)
target_link_libraries(${PROJECT_NAME} XORCryptorLib)
...
```

### Usage
```c++
#include <iostream>
#include "XRC/xor_cryptor.h"

int main() {
    std::string input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis ornare.";
    std::string key   = "secret_key";
    std::string encrypted_result;
    XorCryptor::encrypt(input, key, &encrypted_result);
    std::cout << "\nEncrypted:\n"
              << encrypted_result << "\n\n";

    std::string decrypted_result;
    XorCryptor::decrypt(encrypted_result, key, &decrypted_result);
    std::cout << "Decrypted:\n"
              << decrypted_result << "\n\n";
    return 0;
}
```
