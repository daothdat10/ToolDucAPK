"""Upload/publish a runtime release using the existing Git credential helper.

Maintainer-only utility. Credentials stay in memory and are never printed or
stored in the repository. Upload creates a draft; --publish makes it public.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = "daothdat10/ToolDucAPK"
API = "https://api.github.com/repos/" + REPOSITORY


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--asset-directory", action="append", type=Path, default=[])
    args = parser.parse_args()
    result = subprocess.run(["git", "credential", "fill"], input="protocol=https\nhost=github.com\n\n",
                            capture_output=True, text=True, check=True, cwd=ROOT)
    credentials = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    token = credentials.get("password")
    if not token:
        raise SystemExit("Git credential helper did not provide a GitHub token.")
    headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
               "User-Agent": "DucAPK-Runtime-Publisher", "X-GitHub-Api-Version": "2022-11-28"}

    def api(method, endpoint, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(API + endpoint, data=data, method=method,
                                         headers={**headers, "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)

    manifest = json.loads((ROOT / "runtime-manifest.json").read_text())
    tag = manifest["release_tag"]
    # A public tag lookup does not return draft releases, so list accessible releases.
    releases = api("GET", "/releases?per_page=100")
    release = next((item for item in releases if item["tag_name"] == tag), None)
    if release is None:
        release = api("POST", "/releases", {
            "tag_name": tag, "target_commitish": "main", "name": "DucAPK portable runtime — Windows x64",
            "draft": True, "prerelease": False,
            "body": "Runtime dependency bundle for DucAPK. Clone the repository and run Setup.bat, then DucAPK.bat.\n\n"
                    "Includes Python 3.12 with offline dependency wheels, Il2CppDumper, the custom Cpp2IL build, .NET runtime, JADX, Ghidra and JDK. "
                    "runtime-manifest.json pins SHA-256 checksums. Original tool licenses are retained. "
                    "The companion tool-sources archive preserves Cpp2IL customizations and upstream provenance.\n\n"
                    "No APKs, analysis outputs, API keys or Git credentials are included."})
    names = [item["name"] for item in manifest["assets"]] + [manifest["source_snapshot"]["name"]]
    uploaded = {item["name"]: item for item in api("GET", f"/releases/{release['id']}/assets?per_page=100")}
    if args.publish:
        missing = [name for name in names if name not in uploaded or uploaded[name]["state"] != "uploaded"]
        if missing:
            raise SystemExit("Missing release assets: " + ", ".join(missing))
        for expected in [*manifest["assets"], manifest["source_snapshot"]]:
            item = uploaded[expected["name"]]
            if "size" in expected and item["size"] != expected["size"]:
                raise SystemExit("Remote asset size mismatch: " + expected["name"])
            if item.get("digest") and item["digest"] != "sha256:" + expected["sha256"]:
                raise SystemExit("Remote checksum mismatch: " + expected["name"])
        published = api("PATCH", f"/releases/{release['id']}", {"draft": False})
        print("Published: " + published["html_url"], flush=True)
        return
    from package_runtime import digest
    search_dirs = [ROOT / "dist", *args.asset_directory]
    upload_url = release["upload_url"].split("{", 1)[0]
    for name in names:
        expected = next((item for item in manifest["assets"] if item["name"] == name), manifest["source_snapshot"])
        path = next((folder / name for folder in search_dirs if (folder / name).is_file()), None)
        if path is None or digest(path) != expected["sha256"]:
            raise SystemExit("Missing asset or checksum mismatch: " + name)
        if name in uploaded:
            item = uploaded[name]
            if item["size"] != path.stat().st_size or item["state"] != "uploaded":
                raise SystemExit("Incomplete/conflicting existing asset: " + name)
            remote_digest = item.get("digest")
            if remote_digest and remote_digest != "sha256:" + expected["sha256"]:
                raise SystemExit("Remote checksum mismatch: " + name)
            print("Already uploaded: " + name, flush=True)
            continue
        print(f"Uploading {name} ({path.stat().st_size / 1024**2:.1f} MB)...", flush=True)
        with path.open("rb") as body:
            request = urllib.request.Request(upload_url + "?name=" + urllib.parse.quote(name), data=body,
                method="POST", headers={**headers, "Content-Type": "application/zip", "Content-Length": str(path.stat().st_size)})
            with urllib.request.urlopen(request, timeout=3600) as response:
                item = json.load(response)
        print(f"Uploaded: {item['name']} ({item['size']:,} bytes)", flush=True)
    print("Draft runtime release is ready. Test Setup.bat, then publish with --publish.", flush=True)


if __name__ == "__main__":
    main()
