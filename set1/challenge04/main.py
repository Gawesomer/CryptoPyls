import os
import pathlib

from set1.challenge03.break_single_xor import break_single_xor


def main():
    """
    applies break_single_xor() to hex encoded strings read from file
    prints most likely decrypted result
    """
    # list of dicts {'message': bytes, 'key': bytes, 'score': float}
    res = list()

    input_filename = os.path.join(pathlib.Path(__file__).parent, "input")
    with open(input_filename, "r") as input_file:
        for line in input_file:
            b = bytes.fromhex(line.strip())
            res.append(break_single_xor(b)[0])

    res.sort(key=lambda d: d['score'], reverse=True)
    print(res[0]['message'].decode())


if __name__ == "__main__":
    main()
