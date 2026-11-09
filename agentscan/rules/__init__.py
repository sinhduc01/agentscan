from . import dangerous, exfil, injection, privilege, secrets

ALL_RULES = [secrets, injection, dangerous, exfil, privilege]

__all__ = ["ALL_RULES"]
