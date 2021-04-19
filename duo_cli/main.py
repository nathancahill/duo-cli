import base64
import json
import plistlib
import glob
import os
import os.path
from types import SimpleNamespace
import shutil
import sys

import click
import nacl.pwhash
import nacl.secret
import nacl.exceptions
import passlib.totp
from PyInquirer import prompt
import pyperclip
from rich import print

from .ios_backup import get_backup

PARAMS_KEY = "kBackupEncryptionStoreDerivationParamsDictKey"
TEST_KEY = "kBackupEncryptionStoreEncryptedTestStringKey"
ACCOUNTS_KEY = "DUOSortedAccountInfoArrayKey"

MSGS = SimpleNamespace(
    NO_COPY_HELP="Disable copying to clipboard.",
    PASSWORD_HELP="Duo Mobile backup encryption password.",
    NO_CONFIG_DIR="No configuration found at ~/.duo. Create?",
    CONFIG_REQUIRED="Configuration directory required.",
    PLIST_REQUIRED="Duo Mobile backup plist file required.",
    COPY_PLIST="Copy plist to ~/.duo?",
    CREATED_DIR=(
        "Created directory [default]~/.duo[/default] :white_heavy_check_mark:"
    ),
    ENTER_PATH="Path to Duo Mobile backup plist:",
    NOT_FOUND="Unable to locate Duo Mobile backup plist: {}",
    FOUND_BACKUP="Found com.duosecurity.DuoMobile.plist in iOS backup. Use?",
    BACKUP_NOT_FOUND=(
        "Previously used iOS backup not found. Update ~/.duo/config.json"
    ),
    NO_ACCOUNTS="No accounts are configured in your Duo Mobile backup.",
    CHOOSE_ACCOUNT="Choose account to generate a TOTP:",
    PASSWORD="Enter your Duo Mobile backup encryption password:",
    PW_REQUIRED="Your password is required to decrypt Duo Mobile backup.",
    PW_INCORRECT="Incorrect password",
    STORE_PASSWORD="Store password in ~/.duo/config.json?",
    COPIED="Copied to clipboard :white_heavy_check_mark:",
)


def load_plist(path):
    with open(path, "rb") as f:
        plist = plistlib.load(f, fmt=plistlib.FMT_BINARY)

    return plist


def key_from_plist(plist, password):
    params = plist[PARAMS_KEY]
    salt = params["passwordSaltKey"]
    opslimit = params["opsLimitKey"]
    memlimit = params["memLimitKey"]

    return nacl.pwhash.argon2id.kdf(
        nacl.secret.SecretBox.KEY_SIZE,
        password.encode("utf8"),
        salt,
        opslimit=opslimit,
        memlimit=memlimit,
    )


def b64decrypt(box, cipher, nonce):
    return box.decrypt(base64.b64decode(cipher), base64.b64decode(nonce))


def validate_plist(path):
    plist_path = os.path.expanduser(path.strip())

    if not os.path.exists(plist_path):
        return MSGS.NOT_FOUND.format(path)

    return True


def validate_key(plist, key):
    box = nacl.secret.SecretBox(key)
    [enc, nonce] = plist[TEST_KEY].split(":")

    try:
        b64decrypt(box, enc, nonce)
    except nacl.exceptions.CryptoError:
        return MSGS.PW_INCORRECT

    return True


def validate_password(plist):
    def validate(password):
        key = key_from_plist(plist, password)
        return validate_key(plist, key)

    return validate


def ensure_dir(otp_dir):
    if os.path.exists(otp_dir):
        return False

    answers = prompt(
        [
            {
                "type": "confirm",
                "name": "create",
                "default": True,
                "message": MSGS.NO_CONFIG_DIR,
            },
        ]
    )

    if not answers.get("create"):
        print(MSGS.CONFIG_REQUIRED, file=sys.stderr)
        sys.exit(1)

    os.mkdir(otp_dir)

    if sys.stdout.isatty():
        print(MSGS.CREATED_DIR)

    return True


def write_config(otp_dir, config):
    with open(os.path.join(otp_dir, "config.json"), "w") as f:
        json.dump(config, f)


def ensure_config(otp_dir):
    config_path = os.path.join(otp_dir, "config.json")
    config = {}

    # Load user configuration if available
    if os.path.exists(config_path):
        with open(config_path) as f:
            config = json.load(f)

            if "password" in config:
                config["password"] = base64.b64decode(config["password"])

    # Check if specified plist is valid
    if "plist" in config:
        # Special case for iOS backups
        if config["plist"] == "backup":
            backup = get_backup()

            # If we found a backup, update the config
            if backup:
                config["plist"] = backup
                return config

            # Otherwise, config is invalid
            print(MSGS.BACKUP_NOT_FOUND)
            sys.exit(1)

        if os.path.exists(config["plist"]):
            return config

        print(MSGS.NOT_FOUND.format(config["plist"]), file=sys.stderr)
        sys.exit(1)

    # Fallback to searching ~/.duo
    matches = glob.glob(os.path.join(otp_dir, "*.plist"))

    if len(matches):
        match = matches[0]
        config["plist"] = match
        write_config(otp_dir, config)
        return config

    # Fallback to iOS backups
    backup = get_backup()

    if backup:
        answers = prompt(
            [
                {
                    "type": "confirm",
                    "name": "use",
                    "message": MSGS.FOUND_BACKUP,
                }
            ]
        )

        if answers.get("use"):
            # Store plist config as "backup" so we always find the most recent
            write_config(otp_dir, {**config, "plist": "backup"})

            # Use the most recent path from backup
            config["plist"] = backup
            return config

    # Fallback to prompt
    answers = prompt(
        [
            {
                "type": "input",
                "name": "plist",
                "message": MSGS.ENTER_PATH,
                "validate": validate_plist,
            },
            {
                "type": "confirm",
                "name": "copy_plist",
                "default": True,
                "message": MSGS.COPY_PLIST,
            },
        ]
    )

    if not answers.get("plist"):
        print(MSGS.PLIST_REQUIRED, file=sys.stderr)
        sys.exit(1)

    plist_path = os.path.expanduser(answers.get("plist").strip())

    # Check that plist is valid
    if not os.path.exists(plist_path):
        print(MSGS.NOT_FOUND.format(plist_path), file=sys.stderr)
        sys.exit(1)

    # Copy if needed
    if answers.get("copy_plist"):
        plist_path = shutil.copy(plist_path, otp_dir)

    # Write prompt response to config
    config["plist"] = plist_path
    write_config(otp_dir, config)

    return config


def ensure_plist(config):
    plist = os.path.expanduser(config["plist"])

    if not os.path.exists(plist):
        print(MSGS.NOT_FOUND.format(plist), file=sys.stderr)
        sys.exit(1)

    return load_plist(plist)


def ensure_password(otp_dir, config, plist, first_run=False):
    key = config.get("password")

    if not key:
        questions = [
            {
                "type": "password",
                "name": "password",
                "message": MSGS.PASSWORD,
                "validate": validate_password(plist),
            },
        ]

        if first_run:
            questions.append(
                {
                    "type": "confirm",
                    "name": "save",
                    "default": True,
                    "message": MSGS.STORE_PASSWORD,
                }
            )

        answers = prompt(questions)
        password = answers.get("password")

        if not password:
            print(MSGS.PW_REQUIRED, file=sys.stderr)
            sys.exit(1)

        key = key_from_plist(plist, password)

        if answers.get("save"):
            config["password"] = base64.b64encode(key).decode("ascii")
            write_config(otp_dir, config)

        # Return password before validating again
        return key

    # Validate stored or passed key
    result = validate_key(plist, key)

    if result is not True:
        print(MSGS.PW_INCORRECT, file=sys.stderr)
        sys.exit(1)

    return key


@click.command()
@click.argument("account", default=None, required=False)
@click.option("--no-copy", default=None, is_flag=True, help=MSGS.NO_COPY_HELP)
@click.option("--password", help=MSGS.PASSWORD_HELP)
def main(account, no_copy, password):
    otp_dir = os.path.expanduser("~/.duo")

    first_run = ensure_dir(otp_dir)
    config = ensure_config(otp_dir)
    plist = ensure_plist(config)

    if no_copy:
        config["copy"] = False

    if password:
        config["password"] = key_from_plist(plist, password)

    key = ensure_password(otp_dir, config, plist, first_run)

    accounts = list(map(json.loads, plist[ACCOUNTS_KEY]))

    if not len(accounts):
        print(MSGS.NO_ACCOUNTS, file=sys.stderr)
        sys.exit(1)

    # Use all accounts or filter them to the account passed
    if account:
        filtered = [a for a in accounts if a["serviceName"] == account]
    else:
        filtered = accounts

    # Prompt account list if needed
    if account and len(filtered) == 1:
        account = filtered[0]
    elif not account or len(filtered) > 1:
        anwsers = prompt(
            [
                {
                    "type": "list",
                    "name": "account",
                    "message": MSGS.CHOOSE_ACCOUNT,
                    "choices": [
                        dict(
                            name=f"{a['serviceName']} ({a['displayLabel']})",
                            value=i,
                        )
                        for i, a in enumerate(filtered)
                    ],
                }
            ]
        )

        if "account" not in anwsers:
            sys.exit(1)

        account = accounts[anwsers["account"]]

    # Decrypt encrypted OTP string
    box = nacl.secret.SecretBox(key)
    [enc, nonce] = account["encryptedOTPString"].split(":")
    plainbytes = b64decrypt(box, enc, nonce)

    # Generate TOTP
    t = passlib.totp.TOTP(key=plainbytes, format="raw")
    token = t.generate()

    print(token.token)

    if not no_copy:
        pyperclip.copy(token.token)

        if sys.stdout.isatty():
            print(MSGS.COPIED)
