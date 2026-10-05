import argparse
import plistlib
import sys
from pathlib import Path


REQUIRED_HOOK_MARKERS = (
    b"com.ioscapture.settings",
    b"SecTrustEvaluateWithError",
    b"AFSecurityPolicy",
    b"TSKPinningValidator",
    b"SSL_set_custom_verify",
)


def exactly_one(root: Path, name: str) -> Path:
    matches = list(root.rglob(name))
    if len(matches) != 1:
        raise ValueError(f"expected one {name}, found {len(matches)}")
    return matches[0]


def verify(root: Path, scheme: str) -> None:
    hook = exactly_one(root, "iOSCaptureHook.dylib")
    filter_plist = exactly_one(root, "iOSCaptureHook.plist")
    app = exactly_one(root, "iOSCapture.app")
    executable = app / "iOSCapture"
    info_path = app / "Info.plist"

    if not executable.is_file():
        raise ValueError("manager executable is missing")
    if not info_path.is_file():
        raise ValueError("manager Info.plist is missing")

    hook_bytes = hook.read_bytes()
    missing = [marker.decode("ascii") for marker in REQUIRED_HOOK_MARKERS if marker not in hook_bytes]
    if missing:
        raise ValueError("hook dylib is missing markers: " + ", ".join(missing))

    with filter_plist.open("rb") as handle:
        filter_configuration = plistlib.load(handle)
    filter_rules = filter_configuration.get("Filter", {})
    if filter_rules.get("Bundles") != ["com.apple.UIKit"] or "Classes" in filter_rules:
        raise ValueError("unexpected tweak injection filter")

    with info_path.open("rb") as handle:
        info = plistlib.load(handle)
    if info.get("CFBundleIdentifier") != "com.ioscapture.manager":
        raise ValueError("unexpected manager bundle identifier")

    normalized = str(hook).replace("\\", "/")
    expected_prefix = "/var/jb/" if scheme == "rootless" else "/Library/"
    if expected_prefix not in "/" + normalized.lstrip("/"):
        raise ValueError(f"{scheme} package has an unexpected hook path: {hook}")

    print(f"verified {scheme} package")
    print(f"hook={hook}")
    print(f"manager={app}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--scheme", choices=("rootful", "rootless"), required=True)
    args = parser.parse_args()
    try:
        verify(args.root.resolve(), args.scheme)
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
