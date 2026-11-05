#!/usr/bin/env python3
"""Print every digest that identifies a saved image, one per line."""
import json
import re
import sys
import tarfile

found = {sys.argv[2]}
with tarfile.open(sys.argv[1]) as bundle:
    manifest = json.load(bundle.extractfile('manifest.json'))
    assert len(manifest) == 1, 'Expected exactly one image'
    found.add('sha256:' + re.search(r'[0-9a-f]{64}', manifest[0]['Config']).group(0))
    if 'index.json' in bundle.getnames():
        found.update(m['digest'] for m in json.load(bundle.extractfile('index.json'))['manifests'])
print('\n'.join(sorted(found)))
