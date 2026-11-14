#!/usr/bin/env python3
"""Verify both committed experimental EFUs offline; does not access a printer."""
import hashlib
import json
from pathlib import Path
import zipfile

from patch_scanner_closed import AFTER, PROFILES, inspect_container


def main():
    root = Path(__file__).resolve().parents[1]
    for variant in ['jp', 'us']:
        report = json.loads((root/'reports'/f'{variant}-patch.json').read_text())
        profile = PROFILES[report['source_efu_sha256']]
        filename = f'FWC365TL_{variant.upper()}_scanner_closed_EXPERIMENTAL.efu'
        file = root/'firmware'/filename
        if hashlib.sha256(file.read_bytes()).hexdigest() != report['patched_efu_sha256']:
            raise ValueError(f'{filename}: package SHA-256 mismatch')
        with zipfile.ZipFile(file) as archive:
            if len(archive.infolist()) != 1 or archive.testzip() is not None:
                raise ValueError(f'{filename}: archive validation failed')
            rcx = archive.read(archive.namelist()[0])
        _, metadata, first, _ = inspect_container(rcx)
        if hashlib.sha256(first).hexdigest() != report['patched_part1_sha256']:
            raise ValueError(f'{filename}: first IPL SHA-256 mismatch')
        for offset in profile['offsets']:
            if first[offset:offset+4] != AFTER:
                raise ValueError(f'{filename}: patched instruction mismatch')
        if f'3="{profile["version"]}"' not in metadata or f'12="{profile["target"]}"' not in metadata:
            raise ValueError(f'{filename}: target/version mismatch')
        validation = json.loads((root/'reports'/f'{variant}-arm-validation.json').read_text())
        if validation['status'] != 'passed' or validation['variant'] != variant.upper():
            raise ValueError(f'{filename}: missing ARM execution results')
        print(f'{filename}: SHA-256, ZIP CRC, both IPL checksums/SHA-1, patch and metadata OK')


if __name__ == '__main__':
    main()
