import sys


def query_yes_no(question, default=None):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
            It must be "yes" (the default), "no" or None (meaning
            an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    # Borrowed from here: https://stackoverflow.com/questions/3041986/apt-command-line-interface-like-yes-no-input
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if not default:
        prompt = " [y/n] "
    elif default is True or default.lower() in ("yes", "y"):
        prompt = " [Y/n] "
    elif default is False or default.lower() in ("no", "n"):
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == "":
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' " "(or 'y' or 'n').\n")
