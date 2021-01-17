from Crypto.Cipher import AES
import pathlib
import os

from set1.challenge06.break_repeat_xor import normalized_blk_hamming_avg


def main():
    """
    reads hex encoded strings from file
    prints the line that was most likely encrypted using ECB mode
    """
    # list of dicts {'cipher': bytes, 'score': float, 'line_num': int}
    res = list()

    input_filename = os.path.join(pathlib.Path(__file__).parent, "input")
    with open(input_filename, 'r') as input_file:
        for line_num, line in enumerate(input_file):
            b = bytes.fromhex(line.strip())
            score = normalized_blk_hamming_avg(b, 16, len(b)//16)
            res.append({'cipher': b, 'score': score, 'line_num': line_num})

    res.sort(key=lambda d: d['score'])

    for k, v in res[0].items():
        print("%s: %s" % (k, v))


if __name__ == "__main__":
    main()
