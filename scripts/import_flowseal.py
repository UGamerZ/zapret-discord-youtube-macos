#!/usr/bin/env python3
"""Import pinned BAT configs without interpreting or executing batch commands."""
from pathlib import Path
import json, re, hashlib
root = Path(__file__).resolve().parents[1] / 'Resources/flowseal'
profiles = []
for path in sorted((root / 'configs').glob('general*.bat'), key=lambda p: (p.stem != 'general', p.stem)):
    text = path.read_text(encoding='utf-8-sig')
    start = text.index('--wf-tcp=')
    # Tokenize only the winws argument region. ^! is a literal cmd-escaped !.
    region = text[start:].replace('^\n', ' ').replace('^!', '!')
    tokens = re.findall(r'--[^\s="]+(?:=(?:"[^"]*"|[^\s]+))?', region)
    args, windows = [], {}
    for token in tokens:
        token = token.replace('"', '')
        token = token.replace('%BIN%', '{ROOT}/bin/').replace('%LISTS%', '{ROOT}/lists/')
        token = token.replace('\\', '/')
        if '%' in token.replace('%GameFilterTCP%', '').replace('%GameFilterUDP%', ''):
            raise ValueError(f'Unknown batch variable: {token}')
        if token.startswith('--wf-'):
            key, value = token.split('=', 1)
            if key not in ('--wf-tcp', '--wf-udp'): raise ValueError(key)
            windows[key[5:]] = value
        else:
            args.append(token)
    assert set(windows) == {'tcp', 'udp'} and args
    profiles.append(dict(id=path.stem, name=path.stem, source=path.name,
                         sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                         tcp=windows['tcp'], udp=windows['udp'], arguments=args))
for name in ('list-general-user.txt', 'list-exclude-user.txt', 'ipset-exclude-user.txt'):
    p = root / 'lists' / name
    if not p.exists(): p.write_text('')
(root / 'profiles.json').write_text(json.dumps(profiles, indent=2) + '\n')
print(f'Imported {len(profiles)} exact BAT argument profiles')
