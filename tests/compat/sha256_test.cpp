// SHA-256 against the NIST vectors and the padding boundaries around one and two blocks.
#include <string>
#include <string_view>

#include "sha256.h"
#include "test_support.h"

using livemap::compat::sha256_hex;

int main() {
    compat_test::Suite t;
    const auto hex_of = [](std::string_view text) { return sha256_hex(compat_test::as_bytes(text)); };

    t.check(hex_of("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty input");
    t.check(hex_of("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "abc");
    t.check(hex_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            "448-bit message pads into a second block");
    t.check(hex_of(std::string(55, 'a')) == "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318", "55 bytes fit one block");
    t.check(hex_of(std::string(56, 'a')) == "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a", "56 bytes need a second block");
    t.check(hex_of(std::string(63, 'a')) == "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34", "63 bytes");
    t.check(hex_of(std::string(64, 'a')) == "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb", "one whole block");
    t.check(hex_of(std::string(65, 'a')) == "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0", "one block and a byte");
    t.check(hex_of(std::string(120, 'a')) == "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c", "120 bytes");
    t.check(hex_of(std::string(1000000, 'a')) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "a million a");

    std::string every_byte;
    for (int value = 0; value < 256; ++value) {
        every_byte.push_back(static_cast<char>(value));
    }
    t.check(hex_of(every_byte) == "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880", "every byte value");
    return t.result();
}
