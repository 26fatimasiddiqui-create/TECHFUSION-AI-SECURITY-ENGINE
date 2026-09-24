import urllib.request
import re
import posixpath

base = 'http://localhost:3000'
visited = set()
errors = []

def crawl(path):
    # normalize path
    if '?' in path:
        path = path.split('?')[0]
    if path in visited:
        return
    if not path.startswith('/src/'):
        return
    visited.add(path)
    url = base + path
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            text = resp.read().decode('utf-8', errors='replace')
            for m in re.finditer(r'from\s+["\']([^"\']+)["\']', text):
                imp = m.group(1)
                if imp.startswith('/src/'):
                    crawl(imp)
                elif imp.startswith('.'):
                    dir_path = posixpath.dirname(path)
                    target = posixpath.normpath(posixpath.join(dir_path, imp))
                    crawl(target)
    except Exception as e:
        errors.append((url, str(e)))

crawl('/src/main.jsx')
print(f"Crawled {len(visited)} modules.")
if errors:
    print("ERRORS FOUND:")
    for u, err in errors:
        print(f"  {u} -> {err}")
else:
    print("ALL MODULES TRANSFORMED AND LOADED WITH 200 OK!")
