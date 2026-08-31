"""SYNTHETIC_NON_PHI_ONLY live UDS metadata and connect probe."""
from __future__ import annotations

import argparse
import os
import socket
import stat
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--expect-connect", choices=("allow", "deny"))
    parser.add_argument("--uid", type=int)
    parser.add_argument("--gid", type=int)
    parser.add_argument("--mode", type=lambda value: int(value, 8))
    args = parser.parse_args()
    path = Path(args.path)
    metadata = path.stat()
    if args.uid is not None:
        assert metadata.st_uid == args.uid, (path, metadata.st_uid)
    if args.gid is not None:
        assert metadata.st_gid == args.gid, (path, metadata.st_gid)
    if args.mode is not None:
        assert stat.S_IMODE(metadata.st_mode) == args.mode, (
            path,
            oct(stat.S_IMODE(metadata.st_mode)),
        )
    if args.expect_connect is not None:
        assert stat.S_ISSOCK(metadata.st_mode), path
        connected = False
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(2)
                client.connect(str(path))
                connected = True
        except (PermissionError, ConnectionRefusedError, TimeoutError):
            pass
        assert connected is (args.expect_connect == "allow"), (
            path,
            os.geteuid(),
            os.getegid(),
            os.getgroups(),
            connected,
            args.expect_connect,
        )


if __name__ == "__main__":
    main()
