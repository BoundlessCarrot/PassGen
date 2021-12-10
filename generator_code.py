#!/usr/bin/python3

"""
WISHLIST:
    - Pass phrases (instead of random characters)
    - 2FA
    - Installable on brew, gh-packages, snap, apt, etc.
    - improved search w/ regex for get_from_keychain
    - import function
    - multiple encryption options
    - multiple keychain file support
    - multiple keychain file type support
"""

from secrets import choice
import argparse
from yaml import safe_load, dump
from sys import exit, argv
from pathlib import Path
from getpass import getpass
from passlib.hash import pbkdf2_sha256 as hashfunc, cisco_type7 as keyEncrypt
from Crypto.Cipher import AES as aes
from Crypto.Random import get_random_bytes

CORRECT_PATH = str(Path.home()) + "/.keychain.yaml"


def pass_generator(length=18):
    pass_str = ""
    lookup_table = (
        [chr(x) for x in range(48, 58)]
        + [chr(y) for y in range(65, 91)]
        + [chr(z) for z in range(97, 123)]
    )

    for a in range(length):
        if a % (length // 3) == 0 and a != 0:
            pass_str += "-"
        pass_str += choice(lookup_table)

    return pass_str


def write_to_keychain(tag, user, passwrd, cipher_tag, nonce, key):
    infos = {
        "SITE": tag,
        "USERNAME": user,
        "PASSWORD": passwrd,
        "AES_TAG": cipher_tag,
        "NONCE": nonce,
        "KEY": keyEncrypt.hash(key),
    }
    with open(CORRECT_PATH, "a+") as fp:
        dump(infos, fp, sort_keys=False)
        fp.write("\n\n")


def get_from_keychain(tag):
    match_list = []
    with open(CORRECT_PATH, "r") as fq:
        if len(fq.readlines()) < 3:
            raise SystemExit(LookupError("Keychain is empty!"))
        next(fq)
        line_dict = sorted(safe_load(fq).items())
        for i, tup in enumerate(line_dict):
            if tag in tup[1]:
                found_tag = tup[1]
                user = line_dict[i + 1][1]
                passwrd = line_dict[i + 2][1]
                aes_tag = line_dict[i + 3][1]
                nonce = line_dict[i + 4][1]
                key = line_dict[i + 5][1]
                match_list.append(f"{found_tag}{user}{passwrd}")

    for match in match_list:
        if not match_list:
            print(f"Password for {tag} not found")
            break
        print(
            f"""
            {match[0]}
            {match[1]}
            {decrypt(match[2], aes_tag, nonce, keyEncrypt.decode(key)).decode('utf-8')}
            """
        )

    exit()


def decrypt(ciphertext, cipher_tag, nonce, key):
    cipher = aes.new(key, aes.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, cipher_tag)


def encrypt(passwrd):
    key = get_random_bytes(32)
    cipher = aes.new(key, aes.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(passwrd.encode("utf-8"))
    return ciphertext, tag, cipher.nonce, key


def verify_login():
    my_file = Path(CORRECT_PATH)
    if not my_file.is_file():
        print("Choose a password -->")
        metapass = hashfunc.hash(getpass())
        with open(CORRECT_PATH, "w") as meta:
            meta.write(metapass)
            meta.write("\n")
        return True
    else:
        with open(CORRECT_PATH, "r") as rdr:
            confirmed_pass = rdr.readline().strip()

        pass_test = hashfunc.verify(getpass(), confirmed_pass)

        if pass_test:
            return True
        else:
            print("Incorrect password!")
            return False


if __name__ == "__main__":
    my_parser = argparse.ArgumentParser(
        prog="password generator", description="Create a password of length n"
    )
    my_parser.add_argument(
        "-l",
        "--length",
        help="Length of outputted password, 18 by default",
        type=int,
        metavar="length",
        default=18,
    )
    my_parser.add_argument(
        "-t",
        "--tag",
        help="add the password's use to the keychain",
        type=str,
        metavar="tag",
        default=None,
    )
    my_parser.add_argument(
        "-u",
        "--user",
        help="Add the respective username for the password to the keychain",
        type=str,
        metavar="user",
        default=None,
    )
    my_parser.add_argument(
        "-s",
        "--save",
        help="Saves the generated password (and other info if available) in keychain under aes-256 encryption. Deactivated by default!",
        action="store_true",
    )
    my_parser.add_argument(
        "-f",
        "--find",
        help="Find previously generated passwords by tag if they have been stored in keychain",
        type=str,
        metavar="find",
        default=None,
    )
    my_parser.add_argument(
        "-i",
        "--import_data",
        help="Import a previously created password (as well as other user data) to the keychain",
        action="store_true",
    )
    my_parser.add_argument(
        "-p",
        "--password",
        help="Password flag, used only for importing externally created passwords",
        type=str,
        metavar="password",
        default=None,
    )

    args = my_parser.parse_args()

    if len(argv) <= 3 and "-l" in argv:
        print(f"Generated password:     {pass_generator(args.length)}")
        exit()

    status = verify_login()
    if not status:
        exit()

    if args.find:
        get_from_keychain(args.find)

    if args.import_data:
        passwrd, cipher_tag, nonce, key = encrypt(args.password)
        args.save = True
    else:
        passwrd, cipher_tag, nonce, key = encrypt(pass_generator(args.length))

    if args.save:
        write_to_keychain(args.tag, args.user, passwrd, cipher_tag, nonce, key)

    print(
        f"""
        SITE:   {args.tag}
        USER:   {args.user}
        PASS:   {decrypt(passwrd, cipher_tag, nonce, key).decode('utf-8')}
        STORED: {args.save}
    """
    )

    exit()
