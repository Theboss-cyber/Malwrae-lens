"""Promote a MalwareLens account to admin from the PythonAnywhere console.

Usage (from inside ~/malwarelens, with the app venv active):
    python3 make_admin.py <username_or_email>
"""
import sys

sys.path.insert(0, "/home/theboss/malwarelens")

import app as A  # noqa: E402


def main():
    if len(sys.argv) < 2:
        print("usage: python3 make_admin.py <username_or_email>")
        sys.exit(2)
    target = sys.argv[1].strip()
    uid = A._users.lookup_user_id(target)
    if not uid:
        print(f"user not found: {target!r}")
        sys.exit(1)
    A._users.set_admin(uid, True)
    user = A._users.get_user(uid)
    print(f"OK - @{user['username']} is now an admin.")


if __name__ == "__main__":
    main()