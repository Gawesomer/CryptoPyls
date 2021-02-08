import random
from typing import Callable

from set1.challenge07.ecb_mode import blocks
from set2.challenge11.rand_enc import rand_bytes_gen
from set4.challenge29.md_padding import MDPadding
from set4.challenge30.md4_mac import authenticate_message, is_valid_message
from set4.challenge30.md4 import MD4


def length_extension(
        message: bytes,
        newtext: bytes,
        validate_mac_oracle: Callable[[bytes], bool],
        max_keysize: int = 128) \
        -> bytes:
    """
    params:
        message: authenticated using MD4 keyed MAC
        newtext: text to append to message
        validate_mac_oracle: oracle that returns True if input is authenticated
                             with a valid MAC, False otherwise
        max_keysize: max keysize to try (>= 0)
    returns:
        valid authenticated message (i.e. passes `is_valid_message()`)
        with `newtext` appended to it
    """
    mac = message[:MD4.digest_size]
    oldtext = message[MD4.digest_size:]

    start_state = tuple(
        int.from_bytes(block, "little") for block in blocks(mac, 4)
    )

    for keysize in range(max_keysize):
        glue_padding = MDPadding.apply(
            bytes(keysize)+oldtext, "little"
            )[keysize+len(oldtext):]
        hasher = MD4()
        hasher._message_byte_length = keysize + len(oldtext) + \
            len(glue_padding)
        hasher.A, hasher.B, hasher.C, hasher.D = start_state

        hasher.update(newtext)
        new_mac = hasher.digest()
        new_message = new_mac + oldtext + glue_padding + newtext

        if validate_mac_oracle(new_message):
            return new_message


def main():
    """
    append payload to message while maintaining a valid MAC
    """
    cookie = (b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20"
              b"pound%20of%20bacon")
    key = rand_bytes_gen(random.randint(0, 128))
    authenticated_cookie = authenticate_message(cookie, key)

    def validation_oracle(msg):
        return is_valid_message(msg, key)

    payload = b";admin=true"
    attack_cookie = length_extension(
        authenticated_cookie,
        payload,
        validation_oracle
    )

    assert is_valid_message(attack_cookie, key)
    print(attack_cookie)


if __name__ == "__main__":
    main()
