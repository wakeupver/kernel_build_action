#!/usr/bin/env python3
"""
Apply KernelSU Coccinelle patches to kernel source files.
"""

import subprocess
import sys
import re
from pathlib import Path


def download_cocci_file(filename: str) -> None:
    """Download the cocci file from GitHub."""
    url = f"https://github.com/dabao1955/kernel_build_action/raw/main/kernelsu/{filename}"
    try:
        subprocess.run(
            ["aria2c", url],
            check=True,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Error downloading {filename}: {e}", file=sys.stderr)
        sys.exit(1)


def extract_files_from_cocci(cocci_file: str) -> list[str]:
    """Extract file paths from the cocci file."""
    content = Path(cocci_file).read_text(encoding='utf-8')
    # Match pattern: file in "path/to/file.c"
    matches = re.findall(r'file in "([^"]+)"', content)
    # Remove duplicates while preserving order (Python 3.7+ dict preserves insertion order)
    return list(dict.fromkeys(matches))


def apply_spatch(cocci_file: str, target_file: str) -> None:
    """Apply spatch to a single file."""
    try:
        subprocess.run(
            [
                "spatch",
                "--very-quiet",
                "--sp-file", cocci_file,
                "--in-place",
                "--linux-spacing",
                target_file
            ],
            check=True,
            capture_output=True,
            text=True
        )
        print(f"Applied patch to {target_file}")
    except subprocess.CalledProcessError:
        # Continue on error as per original script (|| true)
        pass


def main() -> None:
    """Main entry point for applying KernelSU Coccinelle patches."""
    # sp_file = "minimal.cocci"
    # sp_file = "classic.cocci"
    sp_file = "nongki.cocci"

    # Download the cocci file
    download_cocci_file(sp_file)

    # Extract files to patch
    files = extract_files_from_cocci(sp_file)

    # Apply patches to each file
    for file_path in files:
        apply_spatch(sp_file, file_path)


if __name__ == "__main__":
    main()
