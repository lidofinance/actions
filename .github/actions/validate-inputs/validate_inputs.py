#!/usr/bin/env python3
"""
Call this script with json-like INPUTS env variable
"""
import os
import json
import re

re_string = r"^[\d\w.,\-/]+$"

input_patterns = {
    "registry_username": r"^[\d\w.,\-/\$]+$",
}


def run():
    inputs = json.loads(os.getenv("INPUTS", ""))
    if not inputs:
        return

    for key, value in inputs.items():
        if isinstance(value, str):
            pattern = input_patterns.get(key, re_string)
            match = validate_string(value, pattern)
            if not match:
                raise ValueError(
                    f"The value of input '{key}' isn't match regex {pattern} "
                    f"and possibly has insecure chars in it"
                )


def validate_string(s, pattern=re_string):
    """
    >>> validate_string("feature/my_branch")
    True
    >>> validate_string("tags/1.2.3-dev")
    True
    >>> validate_string('zzz";echo${IFS}"hello";#')
    False
    >>> validate_string("robot$team-si-rw")
    False
    >>> validate_string("robot$team-si-rw", r"^[\\d\\w.,\\-/\\$]+$")
    True
    """
    return bool(re.match(pattern, s))


if __name__ == "__main__":
    run()
