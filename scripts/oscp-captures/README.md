# OSCP local capture provenance

`capture.py` executes only loopback HTTP discovery/fuzzing and an authenticated SMB file-transfer drill. It also records real `-h` output for 14 Impacket scripts. It never claims to execute Windows/AD attacks. `render.py` renders the recorded text into PNGs for both language trees. These are terminal-output images, not desktop/GUI screenshots.

Prerequisites: Linux, Python 3, Nmap, ffuf, curl, `fonts-dejavu-core`, and free local ports 18080 and 1445. Install the Python packages in `requirements.txt` in a virtual environment and put that environment's `bin` on PATH when capturing. The scripts accept either Kali `impacket-*` aliases or upstream `*.py` entrypoints. The high-port SMB session uses the real Impacket API mini-shell because the 0.13.1 client CLI restricts `-port` to 139/445.

```bash
python3 -m venv /tmp/oscp-captures-venv
/tmp/oscp-captures-venv/bin/pip install -r scripts/oscp-captures/requirements.txt
PATH="/tmp/oscp-captures-venv/bin:$PATH" python3 scripts/oscp-captures/capture.py
/tmp/oscp-captures-venv/bin/python scripts/oscp-captures/render.py
```

`logs/manifest.json` records the capture time, tool versions, commands, type of capture and SHA-256 of each complete text log. Help images visibly state that they are not AD attack results and may display an excerpt; the full output remains in the text log. Capture normalises terminal control sequences and trailing whitespace. Rendering omits blank lines and wraps long text, without inventing results. Execution images retain the substantive output. Fortra's Impacket copyright banner remains in captured help.

The fictional password `LabOnly-123!`, account `learner` and files containing `Training` text belong only to the disposable local exercise. Do not replace committed logs with exam content, actual target secrets or private client data.

The capture script checks port states, HTTP result codes, exact ffuf discoveries, successful SMB download and byte-for-byte file equality. It closes its own client and service processes even after an error. A conflicting port produces a clear error; unrelated services are never killed.
