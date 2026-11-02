#!/usr/bin/env python3
"""Retain bounded Microsoft Catalog GPIO packages without installing them."""
from pathlib import Path
import datetime, hashlib, html, json, re, urllib.parse, urllib.request

ROOT = Path(__file__).resolve().parent / 'private'
IDS = ['2631a7e7-b3bd-4ff0-8350-c5e8ef6f9604',
       'e4857834-58b5-4b7b-b781-f84bab035720']
ROOT.mkdir(exist_ok=True)

def fetch(url, data=None, limit=5 * 1024 * 1024):
    with urllib.request.urlopen(url, data=data, timeout=30) as response:
        body = response.read(limit + 1)
        if len(body) > limit:
            raise ValueError('response exceeds bound')
        return body, response.url

result = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'items': []}
for uid in IDS:
    item = {'update_id': uid}
    for kind, url, data in [
        ('details', 'https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=' + uid, None),
        ('download', 'https://www.catalog.update.microsoft.com/DownloadDialog.aspx',
         urllib.parse.urlencode({'updateIDs': json.dumps([{'size': 0, 'updateID': uid, 'uidInfo': uid}])}).encode()),
    ]:
        body, final = fetch(url, data)
        file = ROOT / (uid + '-' + kind + '.html')
        file.write_bytes(body)
        item[kind] = {'url': url, 'final_url': final, 'bytes': len(body),
                      'sha256': hashlib.sha256(body).hexdigest()}
        text = body.decode('utf-8', 'replace')
        if kind == 'details':
            clean = html.unescape(re.sub('<[^>]*>', ' ', text))
            clean = re.sub(r'\s+', ' ', clean)
            at = clean.find('Supported Hardware IDs')
            item['hardware_text'] = clean[at:at + 750] if at >= 0 else 'not found'
        else:
            urls = sorted(set(re.findall(r'https?://[^\s\'"<>]+\.cab', text)))
            item['packages'] = []
            for url in urls:
                parsed = urllib.parse.urlsplit(url)
                if not parsed.hostname.endswith('.windowsupdate.com'):
                    raise ValueError('unexpected package host')
                url = urllib.parse.urlunsplit(('https', parsed.netloc, parsed.path, parsed.query, parsed.fragment))
                cab, final = fetch(url)
                if not cab.startswith(b'MSCF'):
                    raise ValueError('not a CAB')
                file = ROOT / Path(parsed.path).name
                file.write_bytes(cab)
                item['packages'].append({'url': url, 'final_url': final, 'file': file.name,
                                         'bytes': len(cab), 'sha256': hashlib.sha256(cab).hexdigest()})
    result['items'].append(item)
(ROOT / 'catalog-candidates.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
