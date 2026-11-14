#!/usr/bin/env python3
"""Create an isolated Ghidra Xtensa language for US core-2 query analysis.

Uses the selected Ghidra installation's own sources. Does not modify the stock
Xtensa language. L32R uses the established post-startup pool at 0x80010000;
pre-LITBASE bootstrap loads are outside this model. FLIX semantics are unknown.
Compile the printed .slaspec with Ghidra's support/sleigh before importing.
"""
import argparse,shutil
from pathlib import Path

def prepare(home):
    processors=home/'Ghidra/Processors';source=processors/'Xtensa'
    target=processors/'TX720Xtensa'
    if target.exists():raise ValueError('Refusing to overwrite an existing language module')
    shutil.copytree(source,target)
    patterns=target/'data/patterns'
    if patterns.exists():shutil.rmtree(patterns)
    lang=target/'data/languages'
    for f in lang.glob('*.ldefs'):f.unlink()
    for f in lang.glob('*.sla'):f.unlink()
    (lang/'tx720.ldefs').write_text('''<language_definitions>
<language processor="Xtensa" endian="little" size="32" variant="TX720core2" version="1.0" slafile="tx720_le.sla" processorspec="xtensa.pspec" id="Xtensa:LE:32:TX720core2">
<description>TX720 core 2: fixed extended L32R pool at 80010000; unknown FLIX semantics</description>
<compiler name="default" spec="xtensa.cspec" id="default"/>
</language></language_definitions>\n''')
    (lang/'tx720_le.slaspec').write_text((lang/'xtensa_le.slaspec').read_text())
    p=lang/'xtensaMain.sinc';s=p.read_text()
    before='rel = ((inst_start + 3) & ~3) + ((ri16_i16 | 0xffff0000) << 2);'
    if s.count(before)!=1:raise ValueError('Unexpected Ghidra Xtensa source version')
    p.write_text(s.replace(before,'rel = 0x80010000 + (ri16_i16 << 2);'))
    (lang/'flix.sinc').write_text('''# Provisional 8-byte boundary only; the tested query paths execute no FLIX.
define pcodeop tx720_flix_unknown;
define token txflix(64) txop=(0,3) txbody=(4,63);
:TX720_FLIX_UNKNOWN txbody is txop=0xe & txbody { tx720_flix_unknown(); }
''')
    print(lang/'tx720_le.slaspec')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('ghidra_home',type=Path)
    prepare(p.parse_args().ghidra_home)
