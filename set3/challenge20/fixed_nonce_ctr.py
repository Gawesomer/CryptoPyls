import os
import pathlib

from set1.challenge02.fixed_xor import xor
from set1.challenge06.break_repeat_xor import break_repeat_xor
from set3.challenge19.fixed_nonce_ctr import ctr_encrypt_b64


def main():
    """
    encrypt base64 encoded strings from file with consistent nonce
    break decryption by using `break_repeat_xor()` to get as much of the key
    as possible
    fix key by XORing encrypted messages with the decryption that has been made
    apparent
    """
    encrypted_lines = []
    key = b"YELLOW SUBMARINE"
    nonce = bytes(8)

    input_filename = os.path.join(pathlib.Path(__file__).parent, "input")
    with open(input_filename, "r") as input_file:
        for line in input_file:
            encrypted_lines.append(ctr_encrypt_b64(line, key, nonce))

    repeat_xor_cipher = b''

    longest_line = max(encrypted_lines, key=len)
    blksize = len(longest_line)
    for line in encrypted_lines:
        repeat_xor_cipher += line + longest_line[len(line):]

    res = break_repeat_xor(repeat_xor_cipher, blksize)
    key = res["key"]

    key = xor(
        (b'I\'m rated "R"...this is a warning, ya better void / Poets are '
         b'paranoid, DJ<s/D-s\';;y\'%................................'),
        encrypted_lines[0]
    )
    key += bytes(blksize-len(key))
    key = xor(
        (b"Worse than a nightmare, you don't have to sleep a wink / "
         b"The pain's a migraine e%,&yb5...................."),
        encrypted_lines[12]
    )
    key += bytes(blksize-len(key))
    key = xor(
        (b"Cuz I came back to attack others in spite- / Strike like lightnin',"
         b" It's quite frighteningv..........................."),
        encrypted_lines[1]
    )
    key += bytes(blksize-len(key))
    key = xor(
        (b"The fiend of a rhyme on the mic that you know / It's only one "
         b"capable, breaks-the unbreakable......................."),
        encrypted_lines[17]
    )
    key += bytes(blksize-len(key))
    key = xor(
        (b"For those that oppose to be level or next to this / I ain't a devil"
         b" and this ain't the Exorcist...................."),
        encrypted_lines[11]
    )
    key += bytes(blksize-len(key))
    key = xor(
        (b"Worse than a nightmare, you don't have to sleep a wink / The pain's"
         b" a migraine every time ya think.................."),
        encrypted_lines[12]
    )
    key += bytes(blksize-len(key))
    key = xor(
        (b'You want to hear some sounds that not only pounds but please your '
         b'eardrums; / I sit back and observe the whole s'
         b'cenery'),
        encrypted_lines[26]
    )
    key += bytes(blksize-len(key))

    for i, line in enumerate(encrypted_lines):
        print(xor(key, line).decode())


if __name__ == "__main__":
    main()
