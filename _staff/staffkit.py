"""Staff page toolkit (no schedule data lives in this file).

The staff page is built from the dojang items in Salt & Light Daily.
Its English text and the include/exclude decisions are remembered inside
the encrypted staff.html itself ("memo"), so only new or changed items
ever need a person (or Claude) to translate or decide.

Commands (run from anywhere; paths are explicit):

  python3 staffkit.py prepare  DUMP_DIR WORK_DIR PASSWORD
      DUMP_DIR holds the Daily database exported as JSON files:
        DUMP_DIR/events/*.json, DUMP_DIR/days/*.json, DUMP_DIR/tasks/*.json
      and, optionally, the Staff Notes database:
        DUMP_DIR/meetings/*.json
      Writes WORK_DIR/pending.json listing anything not decided yet.
      Each pending entry needs "include": true/false and, when included,
      English text ("en", or "title"/"note" for events).

  python3 staffkit.py build    DUMP_DIR WORK_DIR PASSWORD
      Merges WORK_DIR/pending.json decisions into the memo, builds the
      page and writes REPO/staff.html. Prints CHANGED or UNCHANGED.

  python3 staffkit.py export   WORK_DIR PASSWORD
      Decrypts the current staff.html to WORK_DIR/current-plain.html.
"""
import base64, glob, json, os, re, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
ITER = 600000
KO = re.compile('[가-힣]')
DOJANG_SOURCES = {'dojang-cal', 'alpha-weekly', 'us-holiday'}


# ---------- crypto ----------
def _key(pw, salt, it):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=it).derive(pw.encode('utf-8'))

def encrypt(plain, pw):
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(_key(pw, salt, ITER)).encrypt(iv, plain.encode('utf-8'), None)
    return json.dumps({'v': 1, 'iter': ITER, 'salt': base64.b64encode(salt).decode(),
                       'iv': base64.b64encode(iv).decode(), 'ct': base64.b64encode(ct).decode()})

def decrypt_current(pw):
    path = os.path.join(REPO, 'staff.html')
    if not os.path.exists(path):
        return ''
    html = open(path, encoding='utf-8').read()
    m = re.search(r'<script id="payload" type="application/json">(.*?)</script>', html, re.S)
    p = json.loads(m.group(1))
    b = lambda s: base64.b64decode(s)
    return AESGCM(_key(pw, b(p['salt']), p['iter'])).decrypt(b(p['iv']), b(p['ct']), None).decode('utf-8')

def staff_json(plain):
    m = re.search(r'var STAFF = (\{.*?\});\n</script>', plain, re.S)
    return json.loads(m.group(1).replace('<\\/', '</')) if m else {}


# ---------- reading the Daily export ----------
def _load(dirpath):
    out = {}
    for f in sorted(glob.glob(os.path.join(dirpath, '*.json'))):
        d = json.load(open(f, encoding='utf-8'))
        # some exports wrap the document as {id, data, version}; a meeting doc has its own 'data' field, so only unwrap the wrapper shape
        if isinstance(d.get('data'), dict) and 'id' in d and set(d) <= {'id', 'data', 'version', 'updatedAt', 'createdAt'}:
            d = d['data']
        out[os.path.basename(f)[:-5]] = d
    return out

def kind_of(title, source=''):
    t = title
    if source == 'us-holiday' or 'US Holiday' in t:
        return 'holiday'
    if any(k in t for k in ['Staff Meeting', 'Instructor Training', '스태프 미팅', '사범 교육']):
        return 'staff'
    if any(k in t for k in ['수업 없음', 'Summer Break', 'No Saturday', 'No class', 'Cancelled', 'cancelled']):
        return 'closed'
    if any(k in t for k in ['Make-up', 'Makeup', 'Schedule change']):
        return 'class'
    if any(k in t for k in ['준비', '공지', '체크', '광고', '마감', '할 일', '리마인더', 'Follow', ' prep', 'Prep ']):
        return 'prep'
    if 'Practice' in t:
        return 'practice'
    return 'event'

def find_link(text):
    m = re.search(r'(https?://\S+|kick\.site/\S+)', text)
    if not m:
        return ''
    u = m.group(1).rstrip('.,)')
    return u if u.startswith('http') else 'https://' + u

def note_of(e):
    return ' · '.join(x for x in [e.get('place', ''), e.get('focus', '')] if x)


def hk(text):
    # excluded (personal) items are remembered by a hash, so their wording never sits in the staff page
    import hashlib
    return '#' + hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]


def memo_from(prev):
    memo = prev.get('memo') or {}
    for k in ('events', 'checks', 'tasks'):
        memo.setdefault(k, {})
    memo.setdefault('excluded_events', [])
    memo.setdefault('excluded_checks', [])
    return memo


def prepare(dump, work, pw):
    os.makedirs(work, exist_ok=True)
    prev = staff_json(decrypt_current(pw))
    memo = memo_from(prev)
    events, days, tasks = _load(os.path.join(dump, 'events')), _load(os.path.join(dump, 'days')), _load(os.path.join(dump, 'tasks'))
    pending = {'events': [], 'checks': [], 'tasks': []}
    for i, e in events.items():
        if i in memo['excluded_events'] or hk(i) in memo['excluded_events']:
            continue
        ko_t, ko_n = e.get('title', ''), note_of(e)
        m = memo['events'].get(i)
        if m and m.get('ko_title') == ko_t and m.get('ko_note') == ko_n:
            continue
        tagged = e.get('source') in DOJANG_SOURCES
        entry = {'id': i, 'date': e.get('date'), 'ko_title': ko_t, 'ko_note': ko_n,
                 'source': e.get('source', ''), 'include': True if (tagged or m) else None,
                 'title': None if KO.search(ko_t) else ko_t, 'note': None if KO.search(ko_n) else ko_n}
        pending['events'].append(entry)
    for date, d in days.items():
        for item in (d.get('focus') or []):
            t = item.get('t', '')
            key = date + '|' + t
            if key in memo['excluded_checks'] or hk(key) in memo['excluded_checks'] or key in memo['checks']:
                continue
            pending['checks'].append({'key': key, 'date': date, 'ko': t, 'include': None,
                                      'en': None if KO.search(t) else t})
    for i, k in tasks.items():
        if k.get('done'):
            continue
        t = k.get('title', '')
        if t in memo['tasks'] or hk(t) in memo['tasks']:
            continue
        pending['tasks'].append({'id': i, 'ko': t, 'include': True, 'en': None if KO.search(t) else t})
    json.dump(pending, open(os.path.join(work, 'pending.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    n = sum(len(v) for v in pending.values())
    print('PENDING', n, '(events %d, checklist items %d, tasks %d)' % (len(pending['events']), len(pending['checks']), len(pending['tasks'])))


def build(dump, work, pw):
    prev_plain = decrypt_current(pw)
    memo = memo_from(staff_json(prev_plain))
    pend_path = os.path.join(work, 'pending.json')
    pending = json.load(open(pend_path, encoding='utf-8')) if os.path.exists(pend_path) else {'events': [], 'checks': [], 'tasks': []}
    problems = []
    for p in pending['events']:
        if p['include'] is False:
            memo['excluded_events'].append(hk(p['id'])); memo['events'].pop(p['id'], None); continue
        if p['include'] is not True or not p.get('title'):
            problems.append('event ' + p['id']); continue
        memo['events'][p['id']] = {'ko_title': p['ko_title'], 'ko_note': p['ko_note'], 'title': p['title'], 'note': p.get('note') or ''}
    for p in pending['checks']:
        if p['include'] is False:
            memo['excluded_checks'].append(hk(p['key'])); continue
        if p['include'] is not True or not p.get('en'):
            problems.append('checklist ' + p['key']); continue
        memo['checks'][p['key']] = p['en']
    for p in pending['tasks']:
        if p['include'] is False:
            memo['tasks'][hk(p['ko'])] = None; continue
        if not p.get('en'):
            problems.append('task ' + p['ko']); continue
        memo['tasks'][p['ko']] = p['en']
    if problems:
        print('NOT BUILT. Undecided or untranslated:', '; '.join(problems)); sys.exit(2)

    events, days, tasks = _load(os.path.join(dump, 'events')), _load(os.path.join(dump, 'days')), _load(os.path.join(dump, 'tasks'))
    out_ev = []
    for i, e in events.items():
        m = memo['events'].get(i)
        if not m or i in memo['excluded_events'] or hk(i) in memo['excluded_events']:
            continue
        ev = {'id': i, 'date': e['date'], 'time': e.get('time', ''), 'end': e.get('end', ''),
              'title': m['title'], 'note': m['note'], 'kind': kind_of(e.get('title', '') + ' ' + m['title'], e.get('source', ''))}
        link = find_link(m['note'])
        if link:
            ev['link'] = link
        out_ev.append(ev)
    out_ev.sort(key=lambda x: (x['date'], x['time'] or '00:00', x['title']))
    checks = {}
    for date, d in sorted(days.items()):
        items = [memo['checks'][date + '|' + it.get('t', '')] for it in (d.get('focus') or [])
                 if (date + '|' + it.get('t', '')) in memo['checks']]
        if items:
            checks[date] = items
    out_tasks = []
    for i, k in tasks.items():
        en = memo['tasks'].get(k.get('title', ''))
        if k.get('done') or not en:
            continue
        out_tasks.append({'title': en, 'start': k.get('from', ''), 'until': k.get('until', '')})
    out_tasks.sort(key=lambda x: x['until'])
    notes = []
    for i, m in _load(os.path.join(dump, 'meetings')).items():
        if not m.get('date') or not m.get('title'):
            continue
        notes.append({'id': i, 'date': m['date'], 'type': m.get('type', ''), 'title': m.get('title', ''),
                      'attendees': m.get('attendees', ''), 'notes': m.get('notes', ''), 'decisions': m.get('decisions', ''),
                      'todos': [{'t': x.get('t', ''), 'who': x.get('who', ''), 'due': x.get('due', ''), 'done': bool(x.get('done'))}
                                for x in (m.get('todos') or []) if x.get('t')],
                      'createdAt': m.get('createdAt', '')})
        pin = _pin_data(m)
        if pin:
            notes[-1]['form'], notes[-1]['data'] = pin
    notes.sort(key=lambda x: (x['date'], x['createdAt']), reverse=True)
    # migrate older plain-text exclusions to hashes
    memo['excluded_events'] = sorted(set(x if x.startswith('#') else hk(x) for x in memo['excluded_events']))
    memo['excluded_checks'] = sorted(set(x if x.startswith('#') else hk(x) for x in memo['excluded_checks']))
    memo['tasks'] = {(hk(k) if v is None and not k.startswith('#') else k): v for k, v in memo['tasks'].items()}
    # drop memo entries for things no longer in the Daily
    memo['events'] = {k: v for k, v in memo['events'].items() if k in events}
    data = {'events': out_ev, 'checklists': checks, 'tasks': out_tasks, 'notes': notes, 'memo': memo}

    plain = render(data)
    if staff_json(prev_plain).get('events') == out_ev and staff_json(prev_plain).get('checklists') == checks \
            and staff_json(prev_plain).get('tasks') == out_tasks and staff_json(prev_plain).get('notes', []) == notes \
            and _strip_data(prev_plain) == _strip_data(plain):
        print('UNCHANGED'); return
    shell = open(os.path.join(HERE, 'login-shell.html'), encoding='utf-8').read()
    shell = shell.replace('{{LOGO}}', _logo()).replace('{{PAYLOAD}}', encrypt(plain, pw))
    open(os.path.join(REPO, 'staff.html'), 'w', encoding='utf-8').write(shell)
    print('CHANGED', len(out_ev), 'events,', len(checks), 'checklist days,', len(out_tasks), 'deadlines')


def _pin_data(m):
    """Template content for the 'Today's Meeting' pin on the staff page.
    Only recent notes (last 21 days) are carried. Leaves out what should not sit on a
    password page: the Alert Student List (student names), revenue/expense KPIs and
    Notes for Owner."""
    form, d = m.get('form') or '', m.get('data') or {}
    if form not in ('round', 'workbook') or not m.get('date'):
        return None
    import datetime
    if (datetime.date.today() - datetime.date.fromisoformat(m['date'])).days > 21:
        return None
    if form == 'round':
        lists = {k: [{'t': x.get('t', ''), 'done': bool(x.get('done'))} for x in (d.get('lists') or {}).get(k, []) if x.get('t')]
                 for k in ('shout', 'appts', 'pending', 'tasks', 'urgent')}
        return form, {'lists': lists, 'alertCount': len([x for x in (d.get('lists') or {}).get('alert', []) if x.get('t')]),
                      'score': d.get('score', ''), 'summary': d.get('summary', '')}
    kpi = {k: v for k, v in (d.get('kpi') or {}).items() if k not in ('rev', 'exp')}
    keep = ('weekOf', 'summary', 'old', 'wins', 'lessons', 'newb', 'events', 'focus', 'one', 'help', 'mgr', 'mgrDate')
    out = {k: d.get(k) for k in keep if d.get(k)}
    out['kpi'] = kpi
    return form, out


def _strip_data(plain):
    return re.sub(r'var STAFF = \{.*?\};\n</script>', '', plain, flags=re.S)

def _logo():
    news = open(os.path.join(REPO, 'index.html'), encoding='utf-8').read()
    return re.search(r'<div class="patch"><img src="([^"]+)"', news).group(1)

def render(data):
    news = open(os.path.join(REPO, 'index.html'), encoding='utf-8').read()
    body = open(os.path.join(HERE, 'staff-body.html'), encoding='utf-8').read()
    def between(s, a, b):
        i = s.index(a); j = s.index(b, i); return s[i:j + len(b)]
    styles = ''.join(re.findall(r'<style>.*?</style>', news, re.S))
    main_inner = between(news, '<main>', '</main>')[len('<main>'):-len('</main>')]
    footer = between(news, '<footer>', '</footer>')
    script = between(news, '<script>', '</script>')
    return (body.replace('{{NEWS_STYLE}}', styles).replace('{{NEWS_MAIN}}', main_inner)
                .replace('{{NEWS_FOOTER}}', footer).replace('{{NEWS_SCRIPT}}', script)
                .replace('{{LOGO}}', _logo())
                .replace('{{DATA}}', json.dumps(data, ensure_ascii=False).replace('</', '<\\/')))


if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'prepare':
        prepare(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == 'build':
        build(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == 'export':
        os.makedirs(sys.argv[2], exist_ok=True)
        open(os.path.join(sys.argv[2], 'current-plain.html'), 'w', encoding='utf-8').write(decrypt_current(sys.argv[3]))
        print('OK')
