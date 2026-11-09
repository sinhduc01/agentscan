from . import dangerous, exfil, injection, privilege, secrets, windows

ALL_RULES = [secrets, injection, dangerous, exfil, privilege, windows]
__all__ = ["ALL_RULES"]
