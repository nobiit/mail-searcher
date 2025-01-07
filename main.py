from datetime import datetime, UTC
from email import message_from_bytes
from email.header import decode_header
from email.utils import parsedate_to_datetime, parseaddr
from fnmatch import fnmatch
from functools import cached_property
from os import environ
from re import findall, match, sub
from sys import stdout
from time import sleep

from imapclient import IMAPClient
from imaplib import IMAP4

now = datetime.now(tz=UTC)


def imap_retry(fn, retry=10):
    for i in range(retry - 1):
        try:
            return fn()
        except IMAP4.abort as ex:
            print(f'[!] Abort: {ex}')
            raise ex
        except (OSError, KeyError, ValueError, AssertionError, IMAP4.error) as ex:
            print(f'[!] Exception: {ex}')
            sleep(1)
            continue
    return fn()


class Tasks:
    def __init__(self, bulk=int(environ.get('TASKS_BULK', 500))):
        self.count = 0
        self.total_count = 0
        self.bulk = bulk
        self._jobs = {}

    @classmethod
    def _to_key(cls, key):
        if isinstance(key, list):
            return cls._to_key(set(key))
        if isinstance(key, set):
            return cls._to_key(tuple(key))
        assert isinstance(key, str) or isinstance(key, tuple)
        return key

    def schedule(self, action, key, value):
        self.count += 1
        self.total_count += 1
        if action not in self._jobs:
            self._jobs[action] = {
                '__type__': 'pairs' if key is not None else 'values'
            }
        d = self._jobs[action]
        if key is not None:
            assert d['__type__'] == 'pairs'
            _key = self._to_key(key)
            if _key not in d:
                d[_key] = {
                    '__type__': 'values',
                    'key': key,
                }
            d = d[_key]
        assert d['__type__'] == 'values'
        d.setdefault('values', []).append(value)

    def get(self, action, purge=False):
        if action not in self._jobs:
            return []
        d = self._jobs[action]
        count = 0
        try:
            if d['__type__'] == 'pairs':
                for key, values in d.items():
                    if key and key[0] == '_':
                        continue
                    count += len(values['values'])
                    yield values['key'], values['values']
                return
            if d['__type__'] == 'values':
                count += len(d['values'])
                yield d['values']
                return
        finally:
            if purge:
                del self._jobs[action]
                self.count -= count
        raise RuntimeError('Invalid type %s' % d['__type__'])


class Addr:
    @classmethod
    def _parse_tokens(cls, raw, trim=True):
        i = -1
        tokens = []
        while i < len(raw) - 1:
            i += 1
            c = raw[i:i + 1]
            if c in [' ', '\r', '\n']:
                if not trim:
                    tokens.append(c)
                continue
            if c in ['@', ',', '|']:
                tokens.append(c)
                continue
            if c in ['<', '(']:
                tokens.append(c)
                c2 = {'<': '>', '(': ')'}.get(c)
                j = raw[i + 1:].index(c2)
                tokens.extend(cls._parse_tokens(raw[i + 1:i + j + 1], trim=False))
                tokens.append(raw[i + j + 1:i + j + 2])
                i += j + 1
                continue
            if c in ['"', "'"] and c in raw[i + 1:]:
                tokens.append(c)
                j = raw[i + 1:].index(c)
                tokens.append(raw[i + 1:i + j + 1])
                tokens.append(raw[i + j + 1:i + j + 2])
                i += j + 1
                continue
            if c == '=' and raw[i + 1:i + 2] == '?':
                tokens.append(raw[i:i + 2])
                k = raw[i + 2:].index('?')
                tokens.append(raw[i + 2:i + k + 2])
                tokens.append(raw[i + k + 2:i + k + 3])
                k2 = raw[i + k + 3:].index('?')
                tokens.append(raw[i + k + 3:i + k + k2 + 3])
                tokens.append(raw[i + k + k2 + 3:i + k + k2 + 4])
                j = raw[i + k + k2 + 4:].index('?=')
                tokens.append(raw[i + k + k2 + 4:i + k + k2 + j + 4])
                tokens.append(raw[i + k + k2 + j + 4:i + k + k2 + j + 6])
                i += k + k2 + j + 5
                continue
            m = match(r'^[\w$/=_.+\[\]!&-]+', raw[i:])
            assert m
            tokens.append(raw[i:i + m.end()])
            i += m.end() - 1
        return tokens

    @classmethod
    def parse_one(cls, raw):
        try:
            tokens = cls._parse_tokens(raw)
        except AssertionError:
            name, address = parseaddr(raw)
            return cls(name, address)
        if tokens[-1] == '>':
            if tokens[0] == '<':
                assert len(tokens) == 5
                return cls(None, ''.join(tokens[1:4]))
            if tokens[0] in ['"']:
                assert len(tokens) == 8
                assert tokens[0] == tokens[2]
                assert tokens[3] == '<'
                return cls(tokens[1], ''.join(tokens[4:7]))
            if tokens[-5] == '<':
                assert len(tokens) >= 6
                if tokens[0] == '=?':
                    return cls(''.join(tokens[:-5]), ''.join(tokens[-4:-1]))
                else:
                    return cls(' '.join(tokens[:-5]), ''.join(tokens[-4:-1]))
        if len(tokens) == 3 and tokens[1] == '@':
            return cls(None, ''.join(tokens[0:3]))
        if tokens[-1] == ')':
            if tokens[3] == '(':
                return cls(''.join(tokens[4:-1]), ''.join(tokens[0:3]))
        raise RuntimeError(f'Invalid: {raw}')

    @classmethod
    def parse(cls, raw):
        parts = cls._parse_tokens(raw, trim=False)
        if not parts:
            return []
        if ',' not in parts:
            return [cls.parse_one(raw)]
        i = parts.index(',')
        if parts[:i]:
            return [cls.parse_one(''.join(parts[:i])), *cls.parse(''.join(parts[i + 1:]))]
        return cls.parse(''.join(parts[i + 1:]))

    def __init__(self, name, address):
        self.name = name
        self.address = address.lower()
        assert self.address
        self.user, self.host = self.address.split('@')
        assert self.user
        assert self.host

    @property
    def is_valid_for_message_id(self):
        return not self.name

    @property
    def is_valid_for_from_address(self):
        return True

    @property
    def is_valid_for_to_address(self):
        return True

    @property
    def is_valid_for_mailing_list(self):
        return True

    def match(self, pattern):
        if isinstance(pattern, list):
            return any(map(lambda x: self.match(x), pattern))
        return match(pattern, self.address)

    def fnmatch(self, pattern):
        if isinstance(pattern, list):
            return any(map(lambda x: self.fnmatch(x), pattern))
        return fnmatch(self.address, pattern)

    def capture(self, pattern, result, many=False):
        if isinstance(pattern, list):
            return any(map(lambda x: self.capture(x, result, many=many), pattern))
        r = self.match(pattern)
        if r:
            if many:
                for k, v in r.groupdict().items():
                    result.setdefault(k, []).append(v)
            else:
                result.update(r.groupdict())
        return r

    def __str__(self):
        if self.name:
            return f'{self.name} <{self.address}>'
        return self.address


class Addrs:
    def __init__(self, *args):
        self._items = set()
        self._add(*args)

    def _in(self, item):
        if not self._items:
            return False
        if isinstance(item, Addr):
            return self._in(item.address)
        assert isinstance(item, str)
        return any(filter(lambda x: x.address == item, self._items))

    def _add(self, *items):
        for item in items:
            if item:
                if isinstance(item, list):
                    self._add(*item)
                    continue
                if isinstance(item, Addrs):
                    self._add(*item.items)
                    continue
                assert isinstance(item, Addr)
                if not self._in(item):
                    self._items.add(item)

    @property
    def items(self):
        return self._items

    def find(self, fn, many=False):
        items = []
        for item in self._items:
            if fn(item):
                items.append(item)
        if not many:
            if items:
                assert len(items) == 1
                return items[0]
            return None
        return items

    def match(self, pattern, **kwargs):
        return self.find(lambda item: item.match(pattern), **kwargs)

    def fnmatch(self, pattern, **kwargs):
        return self.find(lambda item: item.fnmatch(pattern), **kwargs)

    def capture(self, pattern, result, **kwargs):
        return self.find(lambda item: item.capture(pattern, result, many=kwargs.get('many', False)), **kwargs)


class Email:
    FLAG_SEEN = '\\Seen'
    FLAG_ANSWERED = '\\Answered'
    FLAG_STARRED = '\\Starred'
    FLAG_FLAGGED = '\\Flagged'
    FLAG_DELETED = '\\Deleted'
    LABEL_IMPORTANT = '\\Important'
    LABEL_ARCHIVE = '\\Archive'
    LABEL_TRASH = '\\Trash'

    @classmethod
    def parse(cls, m_id, item):
        meta = {}
        msg = None
        for k, v in item.items():
            if isinstance(k, bytes):
                k = k.decode()
            if k.startswith('BODY[') and k[-1] == ']':
                msg = message_from_bytes(v)
                continue
            meta[k] = v
        return cls(msg, meta, m_id)

    def __init__(self, msg, meta, m_id):
        self._msg = msg
        self._meta = meta
        self._m_id = m_id

    @staticmethod
    def decode_header(raw):
        parts = []
        for value, charset in decode_header(raw):
            if isinstance(value, bytes):
                try:
                    value = value.decode(charset or 'utf-8')
                except LookupError:
                    value = value.decode('utf-8', errors='replace')
            assert isinstance(value, str)
            parts.append(value)
        if len(parts) == 1:
            return parts[0]
        return ''.join(parts)

    @property
    def is_valid(self):
        # noinspection PyBroadException
        try:
            return self.seq and self.id and self.message_id and self.from_address
        except Exception:
            return False

    @property
    def seq(self):
        return self._meta['SEQ']

    @property
    def id(self):
        return self._m_id

    @cached_property
    def message_id(self):
        addr = Addr.parse_one(self._msg['Message-ID'])
        assert addr.is_valid_for_message_id
        return addr

    @cached_property
    def date(self):
        try:
            r = parsedate_to_datetime(self._msg['Date'])
        except ValueError:
            r = parsedate_to_datetime(self.decode_header(self._msg['Date']))
        if r.tzinfo is None:
            r = r.astimezone(tz=now.tzinfo)
        return r

    @property
    def days(self):
        return (now - self.date).days

    @cached_property
    def flags(self):
        return list(map(lambda x: x.decode(), self._meta['FLAGS']))

    @property
    def is_seen(self):
        return self.FLAG_SEEN in self.flags

    @cached_property
    def labels(self):
        return list(map(lambda x: x.decode(), self._meta['X-GM-LABELS']))

    @property
    def is_important(self):
        return self.LABEL_IMPORTANT in self.labels

    @cached_property
    def archive_folder(self):
        return f'Year/{self.date.year}'

    @property
    def is_archived(self):
        return self.archive_folder in self.labels

    @cached_property
    def from_address(self):
        addr = Addr.parse_one(self._msg['From'])
        assert addr.is_valid_for_from_address
        return addr

    @cached_property
    def to_address(self):
        try:
            if 'To' in self._msg:
                items = Addr.parse(self._msg['To'])
                for addr in items:
                    assert addr.is_valid_for_to_address
                return Addrs(items)
        except AssertionError:
            pass

    @cached_property
    def cc_address(self):
        try:
            if 'CC' in self._msg:
                items = Addr.parse(self._msg['CC'])
                for addr in items:
                    assert addr.is_valid_for_to_address
                return Addrs(items)
        except AssertionError:
            pass

    @cached_property
    def address(self):
        items = [
            self.from_address,
            self.sender_address,
            self.to_address,
            self.cc_address,
        ]
        return Addrs(*items)

    @cached_property
    def sender_address(self):
        if 'Sender' in self._msg:
            addr = Addr.parse_one(self._msg['Sender'])
            assert addr.is_valid_for_from_address
            return addr

    @cached_property
    def subject(self):
        s = self.decode_header(self._msg['Subject'])
        if s.startswith('Re:'):
            s = s[3:]
        while s.startswith(' '):
            s = s[1:]
        return s.strip().replace('\r\n', '')

    @cached_property
    def subject_tags(self):
        s = self.subject
        items = []
        while s and s[0] == '[':
            i = s.index(']')
            items.append(s[1:i])
            s = s[i + 1:].strip()
        return items

    @cached_property
    def from_name(self):
        return self.decode_header(self.from_address.name)

    @cached_property
    def mailing_list(self):
        if 'X-Mailing-List' in self._msg:
            raw = self._msg['X-Mailing-List']
            addr_raw, subject = raw.split(' ')
            addr = Addr.parse_one(addr_raw)
            assert addr.is_valid_for_mailing_list
            return addr, subject

    def __str__(self):
        return str(self._msg)


class Mail:
    tasks = Tasks()

    def __init__(self, server='imap.gmail.com', user=None, passwd=None, folder='INBOX'):
        self.logger = None
        self._server = server
        self._user = user
        self._passwd = passwd
        self._folder = folder
        self._mail = None

    def _connect(self):
        m = imap_retry(lambda: IMAPClient(self._server, use_uid=True))
        m.login(self._user, self._passwd)
        m.select_folder(self._folder)
        self._mail = m

    def __enter__(self):
        self._connect()
        self.logger = open('mail.log', 'w+')
        return self

    def __exit__(self, *args, **kwargs):
        self._mail.expunge()
        try:
            self._mail.logout()
        except IMAP4.error:
            pass
        self.logger.close()

    def _mail_search(self, args=None, **kwargs):
        args = args or []
        for k, v in kwargs.items():
            if isinstance(v, str) or isinstance(v, datetime):
                args.extend([k.upper(), v])
            else:
                assert v is True
                args.extend([k.upper()])
        return imap_retry(lambda: self._mail.search(args))

    def _mail_fetch(self, message_ids, parts):
        messages = imap_retry(lambda: self._mail.fetch(message_ids, parts))
        for m_id, item in messages.items():
            yield Email.parse(m_id, item)

    def list(self):
        return self._mail_search(all=True)

    def range(self, start_date, end_date):
        if (start_date is None) and (end_date is not None):
            return self._mail_search(before=end_date)
        if (start_date is not None) and (end_date is None):
            return self._mail_search(since=start_date)
        return self._mail_search(since=start_date, before=end_date)

    def search(self, query):
        return imap_retry(lambda: self._mail.gmail_search(query))

    def fetch_messages(self, message_ids, parts, batch=int(environ.get('FETCH_BULK', 100))):
        for i in range(0, len(message_ids), batch):
            yield from self._mail_fetch(message_ids[i:i + batch], parts)

    def set_labels(self, item, labels):
        labels = set(filter(lambda x: x not in [Email.LABEL_ARCHIVE, Email.LABEL_TRASH], labels))
        if set(item.labels) != set(labels):
            self.tasks.schedule('labels', labels, item.id)
            item.labels.extend([item for label in labels if label not in item.labels])
            return True
        return False

    def add_label(self, item, label):
        if label not in item.labels:
            self.tasks.schedule('add_label', label, item.id)
            return True
        return False

    def to_inbox(self, item):
        if 'Inbox' not in item.labels:
            self.tasks.schedule('inbox', None, item.id)
            return True
        return False

    def archive(self, item):
        assert item.labels
        self.tasks.schedule('archive', None, item.id)

    def delete(self, item):
        self.tasks.schedule('delete', None, item.id)

    def commit(self, force=False, retry=10):
        if not force and (self.tasks.count < self.tasks.bulk):
            return

        print(f'----- COMMIT ({self.tasks.count}/{self.tasks.bulk}/{self.tasks.total_count}) -----', flush=True)
        for i in range(retry):
            for labels, items in self.tasks.get('labels', purge=True):
                imap_retry(lambda: self._mail.set_gmail_labels(items, labels))
            for label, items in self.tasks.get('add_label', purge=True):
                imap_retry(lambda: self._mail.add_gmail_labels(items, [label]))
            for items in self.tasks.get('inbox', purge=True):
                imap_retry(lambda: self._mail.move(items, 'Inbox'))
            for items in self.tasks.get('archive', purge=True):
                imap_retry(lambda: self._mail.delete_messages(items))
            for items in self.tasks.get('delete', purge=True):
                imap_retry(lambda: self._mail.copy(items, '[Gmail]/Trash') and self._mail.delete_messages(items))
        print(f'----- DONE ({self.tasks.count}/{self.tasks.total_count}) -----', flush=True)


def diff_items(items_a, items_b):
    adds = []
    removes = []
    unchanged = []

    for item in items_a:
        if item in items_b:
            unchanged.append(item)
        else:
            removes.append(item)

    for item in items_b:
        if item not in items_a:
            adds.append(item)

    return adds, removes, unchanged


def match_of(regex, items):
    for item in items:
        matches = findall(regex, item)
        if matches:
            return matches


def get_labels(item):
    labels = set(filter(lambda x: x[0] == '\\', item.labels))
    matches = {}

    if item.address.capture([r'.+@(?P<name>[\w-]+)\.groups\.io', r'(?P<name>[\w-]+)@(groups\.io|googlegroups\.com|nongnu\.org|cml\.news|w3\.org|lists\.(strace\.io|snort\.org|freedesktop\.org))'], matches, many=True):
        def get_name(v):
            items = {
                'Airspy': ['airspy'],
                'Beta': ['beta'],
                'BITX': ['BITX20'],
                'CML': ['cml-glass', 'cml-film', 'cml-general', 'cml-lighting', 'cml-raw-log-hdr'],
                'ECIR': ['ecir'],
                'Epson': ['EpsonWideFormat'],
                'IBM': ['ibm'],
                'IETF-Http': ['ietf-http-wg'],
                'SDR': ['SDR-Radio'],
                'Seerah': ['asseerah'],
                'Snort': ['snort-devel-bounces', 'snort-sigs', 'snort-users'],
                'SoftRocks': ['softrock40'],
                'Strace': ['strace-devel'],
                'TekScopes': ['TekScopes'],
                'Tinycc': ['Tinycc-devel'],
                'Tmux': ['tmux-users', 'tmux-git'],
                'TWS': ['twsapi'],
                'Wireless': ['CrossCountryWireless'],
            }
            for k, w in items.items():
                if v.lower() in list(map(lambda x: x.lower(), w)):
                    return k

        for name in filter(bool, map(get_name, set(matches['name']))):
            labels.add(f'Other/Groups/{name}')
        if item.days > 3:
            labels.add(Email.LABEL_TRASH)

    if item.address.capture([r'.+@phpclasses\.org'], matches, many=True):
        labels.add(f'Other/Groups/PHP Classes')
        if item.days > 3:
            labels.add(Email.LABEL_TRASH)

    if item.address.capture([r'.+@(.+\.)?(deals\.banggood\.com|getpocket\.com|animoto\.com)'], matches, many=True):
        labels.add(Email.LABEL_TRASH)

    if item.address.match('github@discoursemail.com'):
        labels.add('Other/Groups/GitHub-Education')

    if item.address.fnmatch('*@phpclasses.org'):
        labels.add('Other/Groups/PHP_Classes')

    if item.address.fnmatch('*@*.getsentry.com'):
        matches = findall(r'^([A-Z0-9_]+)-(.+)\s+-\s+', item.subject)
        if len(matches) == 1:
            labels.add('Other/Sentry/%s' % matches[0][0])
            if item.is_important:
                labels.remove(Email.LABEL_IMPORTANT)
            if item.days > 3:
                labels.add(Email.LABEL_TRASH)
        else:
            labels.add('Other/Sentry')

    if item.address.fnmatch('*@youthdev.net', many=True):
        labels.add('Work/YouthDev')

    if item.address.fnmatch('*@elofun.com', many=True):
        labels.add('Work/Elofun')

    if item.address.fnmatch('*@nobidev.com', many=True):
        labels.add('Work/NobiDev')

    # if item.address.fnmatch('*@amazon.com'):
    #     addr = item.address.fnmatch('*@amazon.com')
    #     if 'marketing' in addr.user:
    #         labels.add('Other/Amazon')
    #     else:
    #         labels.add('Partner/Amazon')

    # if item.address.capture(r'.+@(?P<name>[\w-]+).amazon.com', matches):
    #     assert matches['name'] in ['registrar']
    #     labels.add('Partner/Amazon')

    if item.address.fnmatch('*@mbbank.com.vn', many=True):
        labels.add('Banking/MB')
        if item.subject in ['Thong bao giao dich thanh cong', 'Thong bao ket qua giao dich', 'Thông báo thông tin giao dịch thẻ', 'Giao dich chuyen tien tu the ve tai khoan thanh cong'] or match(r'^.+ - Giao dich thanh cong/Notification for completed transaction$', item.subject):
            if item.days < 1:
                labels.add(Email.LABEL_IMPORTANT)
            elif item.is_important:
                labels.remove(Email.LABEL_IMPORTANT)
            if item.days > 7:
                labels.add(Email.LABEL_ARCHIVE)
        if match(r'^.+ - (Giao dich cho phe duyet/Transactions Pending Approval|Giao dịch cho xu ly/ Notification for waiting processing transaction)$', item.subject):
            if item.days < 1:
                labels.add(Email.LABEL_IMPORTANT)
            elif item.is_important:
                labels.remove(Email.LABEL_IMPORTANT)
            if item.days > 7:
                labels.add(Email.LABEL_TRASH)
        if match(r'^(\[.+] )?(Thong bao so phu tai khoan .+ tu ngay .+ den ngay .+|Sao kê thẻ MB .+ tháng .+)$', item.subject):
            labels.add('Banking/SAO_KE')
            if item.days < 30:
                labels.add(Email.LABEL_IMPORTANT)
            elif item.is_important:
                labels.remove(Email.LABEL_IMPORTANT)
            if item.days > 30:
                labels.add(Email.LABEL_ARCHIVE)
        if item.days > 7 and (Email.LABEL_ARCHIVE not in labels and Email.LABEL_TRASH not in labels):
            print(f'OK: {item.subject} ({item.days})')

    if item.address.fnmatch('*@slack.com'):
        labels.add('Other/Slack')
        subject = sub(r'\[Slack] ', '', item.subject)
        if len(subject) > 2 and '\u263a' <= subject[0] <= '\U0001f645':
            subject = subject[2:]
        if match(r'(You\'ve got [0-9]+ unread messages?|.+ sent you (a message|messages)|New messages? (from .+ in .+|in group conversation with .+))', subject):
            if item.days > 7:
                labels.add(Email.LABEL_TRASH)
        if match(r'(.+ mentioned you in .+)', subject):
            if item.days > 7:
                labels.add(Email.LABEL_TRASH)
        if match(r'(Notifications from the .+ workspace for .+|Confirm your email to join .+|.+ on Slack: New Account Details|.+ has invited you to work .+ (in|on) Slack|A message from .+ creators you might have missed|Invited to join .+ creators on Slack|.+ just joined your workspace!|Slack confirmation code: .+)', subject):
            if item.days > 3:
                labels.add(Email.LABEL_TRASH)
        if match(r'(Confirm your email address|Slack account sign in from a new device)', subject):
            if item.days > 3:
                labels.add(Email.LABEL_TRASH)

    if item.address.fnmatch('*@mails.site24x7sp.com'):
        assert item.from_address.name == 'StatusIQ'
        labels.add('Status/StatusIQ')
        if item.days < 1:
            labels.add(Email.LABEL_IMPORTANT)
        elif item.is_important:
            labels.remove(Email.LABEL_IMPORTANT)
        if item.days > 7:
            labels.add(Email.LABEL_TRASH)

    if item.address.fnmatch('*@status-ovhcloud.com'):
        labels.add('Status/OVH')
        if item.days < 1:
            labels.add(Email.LABEL_IMPORTANT)
        elif item.is_important:
            labels.remove(Email.LABEL_IMPORTANT)
        if item.days > 7:
            labels.add(Email.LABEL_TRASH)

    if item.address.fnmatch('*@githubstatus.com'):
        labels.add('Status/GitHub')
        if item.days < 1:
            labels.add(Email.LABEL_IMPORTANT)
        elif item.is_important:
            labels.remove(Email.LABEL_IMPORTANT)
        if item.days > 7:
            labels.add(Email.LABEL_TRASH)

    # if item.address.fnmatch('*@namecheap.com'):
    #     labels.add('Other/NameCheap')

    # if item.address.fnmatch('*@*.nvidia.com'):
    #     labels.add('Other/NVIDIA')

    # if item.address.fnmatch('*@luatvietnam.vn'):
    #     labels.add('Other/LuatVietnam')

    # if item.address.fnmatch('*@google.com'):
    #     labels.add('Other/Google')

    if item.address.fnmatch(['*@github.com', '*@*.github.com'], many=True):
        labels.add('Other/GitHub')
        subject = sub(r'\[GitHub] ', '', item.subject)
        addr = item.address.match(r'(notifications|noreply)@github\.com')
        if addr:
            if addr.name == 'dependabot[bot]':
                if item.is_important:
                    labels.remove(Email.LABEL_IMPORTANT)
                if match(r'\[.+?] ([0-9a-f]{6}: )?Bump ', subject):
                    if item.days > 7:
                        labels.add(Email.LABEL_TRASH)
        if match(r'(Your Dependabot alerts for .+)', subject):
            if item.is_important:
                labels.remove(Email.LABEL_IMPORTANT)
            if item.days > 3:
                labels.add(Email.LABEL_TRASH)
        if match(r'\[.+?] ((Run|PR run) (failed( at startup)?|cancelled): .+)', subject):
            if item.days < 1:
                labels.add(Email.LABEL_IMPORTANT)
            if item.days > 3:
                if item.is_important:
                    labels.remove(Email.LABEL_IMPORTANT)
            if item.days > 7:
                labels.add(Email.LABEL_TRASH)
        if match(r'\[.+?] (A security advisory on .+ affects at least one of your repositories|Your repository has dependencies with security vulnerabilities)', subject):
            if item.is_important:
                labels.remove(Email.LABEL_IMPORTANT)
            if item.days > 3:
                labels.add(Email.LABEL_TRASH)
        if match(r'(Repository transfer from .+|Subscribed to .+|.+ has invited .+ to join .+|.+ has (joined|accepted) the .+)', subject):
            labels.add(Email.LABEL_IMPORTANT)
            if item.days > 7:
                labels.add(Email.LABEL_TRASH)
        if match(r'\[.+?] (Release .+|.+ \((Issue|PR) #[0-9]+\))', subject):
            labels.add(Email.LABEL_IMPORTANT)
            if item.days > 7:
                labels.add(Email.LABEL_TRASH)
        if match(r'You\'ve used [0-9]+% of included services for the .+ account', subject):
            if item.is_important:
                labels.remove(Email.LABEL_IMPORTANT)
            if item.days > 7:
                labels.add(Email.LABEL_TRASH)

    # if item.address.fnmatch('*@sketchfab.com'):
    #     labels.add('Other/Sketchfab')

    # if item.address.fnmatch('*@*.techsoup.org'):
    #     labels.add('Other/TechSoup')

    # if item.address.fnmatch('*@*.banggood.com'):
    #     labels.add('Other/Banggood')

    # if item.address.fnmatch('*@facebookmail.com'):
    #     labels.add('Other/Facebook')

    if item.address.fnmatch('*@*.tiktok.com'):
        labels.add('Other/Tiktok')
        if item.from_address.address == 'sellersupport@shop.tiktok.com':
            if item.is_important:
                labels.remove(Email.LABEL_IMPORTANT)
            if item.days > 3:
                labels.add(Email.LABEL_TRASH)

    if item.address.fnmatch('*@itviec.com'):
        labels.add('Other/HR')
        if item.from_address.match(r'^itviec\+(jobrobot)\+.+@itviec.com$'):
            if item.days > 3:
                labels.add(Email.LABEL_TRASH)
        if item.from_address.match(r'^itviec\+(welcome|ijm|discussion|candidate|survey|privacy|userreview|gemini|upr|cr)\+.+@itviec.com$'):
            if item.days > 7:
                labels.add(Email.LABEL_TRASH)

    if item.address.fnmatch(['*@samsung.com', '*@*.samsung.com']):
        labels.add('Other/SamSung')
        if 'QC' in item.subject_tags:
            if item.is_important:
                labels.remove(Email.LABEL_IMPORTANT)
            if item.days > 3:
                labels.add(Email.LABEL_TRASH)

    if item.address.fnmatch(['*@info.vietcombank.com', '*@info.vietcombank.com.vn']):
        labels.add('Banking/Vietcombank')
        if 'QC' in item.subject_tags:
            if item.is_important:
                labels.remove(Email.LABEL_IMPORTANT)
            if item.days > 3:
                labels.add(Email.LABEL_TRASH)
        if 'TB' in item.subject_tags:
            if item.days < 7:
                labels.add(Email.LABEL_IMPORTANT)
            elif item.is_important:
                labels.remove(Email.LABEL_IMPORTANT)
            if item.days > 30:
                labels.add(Email.LABEL_ARCHIVE)
        if item.subject in ['Thông báo giao dịch thẻ/ Vietcombank card transaction notification', 'Biên lai chuyển tiền qua tài khoản', 'Biên lai chuyển tiền qua tài khoản/ thẻ', 'Đăng ký dịch vụ nạp rút ví điện tử/ E-wallet Cash in – cash out registration', 'Thông báo giao dịch chuyển khoản không thành công', 'Biên lai thanh toán']:
            if item.days < 1:
                labels.add(Email.LABEL_IMPORTANT)
            elif item.is_important:
                labels.remove(Email.LABEL_IMPORTANT)
            if item.days > 7:
                labels.add(Email.LABEL_ARCHIVE)

    for item in ['Groups', 'Partner', 'Banking', 'Status', 'Other/Groups', 'Other/Sentry']:
        if list(filter(lambda x: x.startswith(f'{item}/'), labels)):
            labels.add(item)

    return labels


def requeue(label):
    with Mail(user=environ.get('IMAP_USER'), passwd=environ.get('IMAP_PASSWD'), folder=label) as m:
        print('Connected !', flush=True)
        message_ids = m.list()
        parts = ['BODY.PEEK[HEADER.FIELDS (MESSAGE-ID SUBJECT)]', 'X-GM-MSGID', 'X-GM-THRID', 'X-GM-LABELS', 'FLAGS']
        messages = m.fetch_messages(message_ids, parts, batch=20000)
        print('Starting ...', flush=True)
        i = 0
        n = len(message_ids)
        for item in messages:
            i += 1
            try:
                if m.to_inbox(item):
                    print(f'[{i}/{n}/{m.tasks.count}/{m.tasks.total_count}]{item.message_id} ({item.subject}) -> {item.labels}')
                m.commit()
            finally:
                stdout.flush()
        m.commit(force=True)
        print(f'[{i}/{n}/{m.tasks.count}/{m.tasks.total_count}] OK')

    print('OK')


def main(f=None):
    with Mail(user=environ.get('IMAP_USER'), passwd=environ.get('IMAP_PASSWD')) as m:
        print('Connected !', flush=True)
        message_ids = f(m) if f else m.list()
        parts = ['BODY.PEEK[HEADER.FIELDS (MESSAGE-ID FROM TO CC SENDER X-ORIGINAL-TO X-MAILING-LIST SUBJECT DATE)]', 'X-GM-MSGID', 'X-GM-THRID', 'X-GM-LABELS', 'FLAGS']
        if environ.get('DEBUG_MAIL'):
            parts.extend(['ENVELOPE', 'RFC822'])
        messages = m.fetch_messages(message_ids, parts)
        print('Starting ...', flush=True)
        i = 0
        n = len(message_ids)
        for item in messages:
            i += 1
            if not item.is_valid:
                print(f'[{i}/{n}] INVALID')
                continue
            try:
                try:
                    labels = get_labels(item)
                except Exception as ex:
                    print(f'[{i}/{n}/{m.tasks.count}/{m.tasks.total_count}][Exception] {item.subject}: {ex.__class__.__name__}({ex})')
                    if environ.get('RAISE_FOR_EXCEPTION'):
                        raise ex
                    m.add_label(item, 'Error')
                    continue
                if not labels:
                    labels.add('Unknown')
                    print(f'UNKNOWN => ({item.from_address.address}) {item.subject}')
                    m.logger.write(('-' * 30) + '\n')
                    m.logger.write(str(item))
                invalid_labels = list(filter(lambda x: x[0] != '\\' and x not in labels and not match(r'^Year/.+', x), item.labels))
                if invalid_labels and ('Unknown' not in invalid_labels) and ('Error' not in invalid_labels):
                    print(f'[{i}/{n}/{m.tasks.count}/{m.tasks.total_count}][Conflict] {item.subject} ({invalid_labels} -> {labels})')
                    m.add_label(item, 'Conflict')
                    continue
                if Email.LABEL_ARCHIVE in labels:
                    labels.add(item.archive_folder)
                if m.set_labels(item, labels):
                    print(f'[{i}/{n}/{m.tasks.count}/{m.tasks.total_count}]{item.message_id} ({item.subject}) {item.labels} -> {labels}')
                if Email.LABEL_ARCHIVE in labels:
                    print(f'ARCHIVE => ({item.from_address.address}) {item.subject}')
                    m.archive(item)
                if Email.LABEL_TRASH in labels:
                    print(f'DELETE => ({item.from_address.address}) {item.subject}')
                    m.delete(item)
            finally:
                m.commit()
                stdout.flush()
        m.commit(force=True)
        print(f'[{i}/{n}/{m.tasks.count}/{m.tasks.total_count}] OK')

    print('OK')


def requeue_all():
    for year in list(reversed(list(map(lambda x: 2025 - x, range(8))))):
        try:
            requeue(f'Year/{year}')
        except IMAP4.error as ex:
            print(f'[Exception]: {ex}')


def mail_plus():
    # main(lambda m: m.range(None, datetime(2021, 6, 1)))
    searches = [
        'from:groups.io',
        'from:googlegroups.com',
        'from:getsentry.com',
        'from:slack.com',
        'from:mails.site24x7sp.com',
        'from:github.com',
        'from:tiktok.com',
        'from:itviec.com',
        'from:snort.org',
        'from:status-ovhcloud.com',
        'from:lists.freedesktop.org',
        'from:mbbank.com.vn',
        'from:githubstatus.com',
        'from:w3.org',
        'to:w3.org',
        'from:deals.banggood.com',
        'from:phpclasses.org',
        'from:getpocket.com',
        'from:animoto.com',
        'from:tiktok.com',
        'from:samsung.com',
        'from:vietcombank.com',
    ]
    for item in searches:
        main(lambda m: m.search(item))


if __name__ == '__main__':
    # requeue_all()
    mail_plus()
