"""Capture actual local tool output; never connects to external lab targets."""
from pathlib import Path
from datetime import datetime, timezone
from importlib.metadata import version
import hashlib, http.server, json, os, re, shlex, shutil, socket
import subprocess, sys, tempfile, threading, time

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / 'logs'
TOOLS = ['smbclient','smbserver','GetADUsers','lookupsid','GetUserSPNs','GetNPUsers',
         'mssqlclient','wmiexec','psexec','smbexec','secretsdump','getTGT','getST','ticketConverter']
OUT.mkdir(exist_ok=True)
records = []

def exe(name):
    for candidate in (f'impacket-{name}', f'{name}.py'):
        found = shutil.which(candidate)
        if found:
            return found
    raise RuntimeError(f'Install Impacket and expose its scripts on PATH: {name}')

def save(name, cmd, output, kind='help', shown=None):
    # Terminal control sequences and trailing whitespace are normalised; substantive output is retained.
    clean = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', output).replace('\r\n','\n').replace('\r','\n')
    clean = '\n'.join(line.rstrip() for line in clean.splitlines())
    text = '$ ' + (shown or shlex.join(cmd)) + '\n' + clean.rstrip() + '\n'
    path = OUT / f'{name}.txt'; path.write_text(text)
    records.append({'id':name,'kind':kind,'command':shown or shlex.join(cmd),
                    'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})

def run(cmd,cwd=None,**kw):
    p=subprocess.run(cmd,cwd=cwd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=45,**kw)
    if p.returncode:
        raise RuntimeError(f'{shlex.join(cmd)} returned {p.returncode}: {p.stdout}\n{p.stderr}')
    return p.stdout

for name in TOOLS:
    cmd=[exe(name),'-h']
    save(name+'-help',cmd,run(cmd),shown=f'{Path(cmd[0]).name} -h')

for program in ('nmap','ffuf','curl'):
    if not shutil.which(program):
        raise RuntimeError(f'Missing {program}; install it with your distribution')

# Fail clearly on a conflict; do not stop any existing service.
for port in (18080,1445):
    with socket.socket() as s:
        s.bind(('127.0.0.1',port))

with tempfile.TemporaryDirectory(prefix='oscp-tools-') as td:
    base=Path(td)
    for folder in ('web/admin','share','downloads'):
        (base/folder).mkdir(parents=True)
    (base/'web/index.html').write_text('Training home\n')
    (base/'web/admin/index.html').write_text('Training admin page\n')
    (base/'web/login').write_text('Training login page\n')
    (base/'words.txt').write_text('admin\nlogin\nmissing\n')
    (base/'share/note.txt').write_text('OSCP practice: controlled SMB transfer\n')
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,directory=str(base/'web'),**kwargs)
        def log_message(self,*args):pass
    class Server(http.server.ThreadingHTTPServer):
        # Nmap deliberately resets some probes; those are not HTTP application failures.
        def handle_error(self,request,client_address):pass
    http=Server(('127.0.0.1',18080),Handler)
    thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start()
    smb=None
    child=None
    try:
        cmd=['nmap','--unprivileged','-sT','-Pn','-n','-p','18080,18081','-sV','127.0.0.1']
        output=run(cmd);assert '18080/tcp open' in output
        save('nmap-http',cmd,output,'executed-local-service')
        cmd=['curl','-sS','-i','http://127.0.0.1:18080/']
        output=run(cmd);assert '200 OK' in output and 'Training home' in output
        save('curl-http',cmd,output,'executed-local-service')
        cmd=['ffuf','-u','http://127.0.0.1:18080/FUZZ','-w','words.txt','-mc','all',
             '-t','1','-rate','5','-noninteractive','-of','json','-o','paths.json']
        output=run(cmd,cwd=base)
        results=json.loads((base/'paths.json').read_text())['results']
        status={x['input']['FUZZ']:x['status'] for x in results}
        assert status=={'admin':301,'login':200,'missing':404},status
        save('ffuf-http',cmd,output,'executed-local-service')
        server_cmd=[exe('smbserver'),'LAB','share','-smb2support','-ip','127.0.0.1',
                    '-port','1445','-username','learner','-password','LabOnly-123!']
        with (base/'server.log').open('w') as log:
            smb=subprocess.Popen(server_cmd,cwd=base,stdout=log,stderr=log,text=True)
            for _ in range(100):
                if smb.poll() is not None:raise RuntimeError((base/'server.log').read_text())
                try:
                    with socket.create_connection(('127.0.0.1',1445),timeout=.1):break
                except OSError:time.sleep(.05)
            else:raise RuntimeError('Own local SMB server did not start')
            client_code='from impacket.smbconnection import SMBConnection; from impacket.examples.smbclient import MiniImpacketShell; s=SMBConnection("127.0.0.1","127.0.0.1",sess_port=1445); s.login("learner","LabOnly-123!","LAB"); MiniImpacketShell(s,None).cmdloop()'
            client=[sys.executable,'-c',client_code]
            # A PTY records the commands as well as the real interactive response.
            import pexpect
            child=pexpect.spawn(client[0],client[1:],cwd=str(base/'downloads'),encoding='utf-8',timeout=15)
            transcript=[]
            child.expect('# ');transcript.append(child.before+child.after)
            for command in ['shares','use LAB','ls','get note.txt']:
                child.sendline(command);child.expect('# ');transcript.append(child.before+child.after)
            child.sendline('exit');child.expect(pexpect.EOF);transcript.append(child.before)
            assert (base/'downloads/note.txt').read_bytes()==(base/'share/note.txt').read_bytes()
            save('smb-session',client,''.join(transcript),'executed-local-service',
                 shown='python3 '+shlex.join(client[1:]))
            cmd=['sha256sum','share/note.txt','downloads/note.txt']
            output=run(cmd,cwd=base)
            output+='\n$ cmp share/note.txt downloads/note.txt && echo "MATCH: same file bytes"\n'
            run(['cmp','share/note.txt','downloads/note.txt'],cwd=base)
            output+='MATCH: same file bytes\n'
            save('file-integrity',cmd,output,'executed-local-service')
    finally:
        if child is not None:
            child.close(force=True)
        http.shutdown();http.server_close();thread.join(timeout=2)
        if smb is not None:
            smb.terminate()
            try:smb.wait(timeout=5)
            except subprocess.TimeoutExpired:smb.kill();smb.wait()

manifest={'captured_at_utc':datetime.now(timezone.utc).isoformat(),
          'platform':'Linux container; loopback services only',
          'impacket_version':version('impacket'),
          'nmap_version':run(['nmap','--version']).splitlines()[0],
          'ffuf_version':run(['ffuf','-V']).strip(),
          'images':'faithful text renderings, not desktop screenshots',
          'records':records}
(OUT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(f'PASS: {len(records)} real captures; Nmap/ffuf/HTTP/SMB results and transferred bytes verified')
