"""Render captured terminal text exactly, retaining attribution and provenance."""
from pathlib import Path
import hashlib,json,textwrap
from PIL import Image,ImageDraw,ImageFont
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
manifest=json.loads((HERE/'logs/manifest.json').read_text())
font_path=Path('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf')
if not font_path.exists():raise RuntimeError('Install fonts-dejavu-core for reproducible text metrics')
font=ImageFont.truetype(str(font_path),18)
small=ImageFont.truetype(str(font_path),15)
for record in manifest['records']:
    source=HERE/'logs'/f"{record['id']}.txt"
    assert hashlib.sha256(source.read_bytes()).hexdigest()==record['sha256']
    lines=source.read_text().splitlines()
    # Help is visibly labelled an excerpt; raw logs remain complete.
    excerpt=record['kind']=='help' and len(lines)>30
    if excerpt:lines=lines[:30]
    # ffuf progress/spinner lines are retained in the raw log; select nonempty output.
    lines=[line for line in lines if line.strip()]
    wrapped=[]
    for line in lines:
        wrapped.extend(textwrap.wrap(line,112,replace_whitespace=False,drop_whitespace=False) or [''])
    if excerpt:wrapped.append('[help excerpt; complete output in logs/]')
    height=140+len(wrapped)*26+40
    im=Image.new('RGB',(1320,height),'#0e1726');d=ImageDraw.Draw(im)
    d.rounded_rectangle((14,14,1306,height-14),radius=14,fill='#142033',outline='#34455f',width=2)
    label='REAL LOCAL SERVICE EXECUTION' if record['kind']!='help' else 'REAL TOOL HELP / NOT AN AD ATTACK RESULT'
    d.text((36,32),label,font=small,fill='#71e4bb')
    d.text((36,61),record['id']+' | '+manifest['captured_at_utc'][:10]+' UTC',font=font,fill='#ffffff')
    d.line((36,98,1280,98),fill='#34455f',width=2)
    for i,line in enumerate(wrapped):
        d.text((36,120+i*26),line,font=font,fill='#7dd3fc' if line.startswith('$') else '#e1e8f4')
    for lang in ('docs','docs-ko'):
        out=ROOT/lang/'assets/oscp-practical'/f"{record['id']}.png"
        out.parent.mkdir(parents=True,exist_ok=True);im.save(out,optimize=True)
print(f'Rendered {len(manifest["records"])} PNGs per language from verified raw logs')
