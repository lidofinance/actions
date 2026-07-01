#!/usr/bin/env python3
"""
Call this script with json-like INPUTS env variable
"""
import os
import json
import re

re_string = r"^[\d\w.,\-/]+$"


def run():
    inputs = json.loads(os.getenv("INPUTS", ""))
    if not inputs:
        return
    for key, value in inputs.items():
        if isinstance(value, str):
            match = validate_string(value)
            if not match:
                raise ValueError(
                    f"The value of input '{key}' isn't match regex {re_string} "
                    f"and possibly has insecure chars in it"
                )


def validate_string(s):
    """
    >>> validate_string("feature/my_branch")
    True
    >>> validate_string("tags/1.2.3-dev")
    True
    >>> validate_string("tags/1.2.3-dev")
    True
    >>> validate_string('zzz";echo${IFS}"hello";#')
    False
    """
    return bool(re.match(re_string, s))


if __name__ == "__main__":
    run()
