import random
from typing import Callable

from set1.challenge07.ecb_mode import blocks
from set2.challenge11.rand_enc import rand_bytes_gen
from set4.challenge28.sha1 import SHA1
from set4.challenge28.sha1_mac import authenticate_message, is_valid_message
from set4.challenge29.md_padding import MDPadding


def length_extension(
        message: bytes,
        newtext: bytes,
        validate_mac_oracle: Callable[[bytes], bool],
        max_keysize: int = 128) \
        -> bytes:
    """
    params:
        message: authenticated using SHA-1 keyed MAC
        newtext: text to append to message
    returns:
        valid autheniticated message (i.e. passes `is_valid_message()`)
        with `newtext` appended to it
    """
    mac = message[:20]
    oldtext = message[20:]

    start_state = tuple(
        int.from_bytes(block, "big") for block in blocks(mac, 4)
    )
    hasher = SHA1()

    for i in range(max_keysize):
        glue_padding = MDPadding.apply(bytes(i)+oldtext)[i+len(oldtext):]
        hasher._message_byte_length = i + len(oldtext) + len(glue_padding)
        hasher._h = start_state
        hasher._unprocessed = b''

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
