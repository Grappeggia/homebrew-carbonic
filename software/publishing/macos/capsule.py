"""Private, exact-source Git capsules and OpenSSL 3 CMS transport primitives.

No networking or publication. Callers must keep capsules, receipts and subprocess
logs private; a capsule contains plaintext private source. CMS is encryption, not
sender authentication: bind its hash and recipient to a separately trusted run.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile

ALLOWLIST = ('.gitignore', 'software', 'tooling', 'design-r4b/firmware/common',
             'design-r5/tools', '.github/workflows/carbonic-release.yml',
             '.github/workflows/carbonic.yml')
PARITY_SCOPES = ('software/apps/carbonic', 'software/packages/acquisition-core',
                 'design-r4b/firmware/common', 'software/publishing/macos',
                 '.github/workflows/carbonic-release.yml')
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_MEMBER = 32 * 1024 * 1024
MAX_ENTRIES = 10000
CONFIG = (b'[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n'
          b'\tbare = false\n\tlogallrefupdates = false\n\tsymlinks = true\n'
          b'\tignorecase = false\n')
METADATA = {'.carbonic/manifest.json', '.carbonic/return.pem'}
PROJECT = Path(__file__).resolve().parents[3]


class CapsuleError(ValueError):
    """A fixed, non-sensitive failure reason, suitable for bounded CLI output."""


def _require(condition, code):
    if not condition:
        raise CapsuleError(code)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _hex(value, length):
    _require(isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % length, value),
             'invalid_digest')
    return value


def _env():
    # Do not inherit GIT_CONFIG_*, alternates, replacement objects, credentials,
    # user attributes, hooks, tracing, LD_PRELOAD or subprocess token variables.
    return {'PATH': os.environ.get('PATH', os.defpath), 'LC_ALL': 'C',
            **({'HOME': os.environ['HOME']} if 'HOME' in os.environ else {}),
            'GIT_CONFIG_NOSYSTEM': '1',
            'GIT_CONFIG_SYSTEM': os.devnull, 'GIT_CONFIG_GLOBAL': os.devnull,
            'GIT_ATTR_NOSYSTEM': '1', 'GIT_NO_REPLACE_OBJECTS': '1',
            'GIT_NO_LAZY_FETCH': '1', 'GIT_TERMINAL_PROMPT': '0',
            'GIT_OPTIONAL_LOCKS': '0',
            **{k: str(PROJECT / 'design-r5/build/runtime/tmp')
               for k in ('TMPDIR', 'TMP', 'TEMP')},
            'XDG_CACHE_HOME': str(PROJECT / 'design-r5/build/runtime/cache'),
            'RANDFILE': str(PROJECT / 'design-r5/build/runtime/tmp/openssl-rand')}


def _run(args, *, data=None, cwd=None):
    try:
        result = subprocess.run(args, input=data, cwd=cwd, env=_env(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=600, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CapsuleError('subprocess_unavailable') from exc
    _require(result.returncode == 0, 'subprocess_failed')
    return result.stdout


def _git(repo, *args, data=None):
    return _run(['git', '-c', 'core.hooksPath=' + os.devnull,
                 '-c', 'core.attributesFile=' + os.devnull,
                 '-c', 'protocol.allow=never', '-C', str(repo), *args], data=data)


def _temporary(parent=None):
    if parent is None:
        parent = PROJECT / 'design-r5/build/runtime/tmp'
        parent.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(prefix='capsule-', dir=parent)


def _path(name):
    _require(isinstance(name, str) and bool(name) and '\\' not in name
             and ':' not in name and all(ord(c) >= 32 and ord(c) != 127 for c in name),
             'unsafe_path')
    parts = name.split('/')
    _require(all(p not in ('', '.', '..') for p in parts), 'unsafe_path')
    _require(not PurePosixPath(name).is_absolute(), 'unsafe_path')
    # Also exclude case-insensitive filesystem aliases of Git's control paths.
    _require(all(p.casefold() not in ('.git', '.carbonic') for p in parts[1:]),
             'unsafe_path')
    return name


def _selected(path):
    return any(path == p or path.startswith(p + '/') for p in ALLOWLIST)


def _tree(repo, source):
    _require(_git(repo, 'cat-file', '-t', source).strip() == b'commit', 'not_commit')
    root = _git(repo, 'rev-parse', source + '^{tree}').decode().strip()
    trees, files = {root}, {}
    for record in _git(repo, 'ls-tree', '-r', '-t', '-z', source).split(b'\0'):
        if not record:
            continue
        head, rawpath = record.split(b'\t', 1)
        mode, kind, oid = head.decode('ascii').split()
        path = rawpath.decode('utf-8')
        if kind == 'tree':
            trees.add(oid)
        else:
            files[path] = (mode, oid)
    selected = {p: value for p, value in files.items() if _selected(p)}
    _require(selected, 'empty_selection')
    _require(all(m in ('100644', '100755', '120000') for m, _ in selected.values()),
             'selected_submodule_or_mode')
    for path in selected:
        _path(path)
    _require(len({p.casefold() for p in selected}) == len(selected), 'path_collision')
    return root, trees, files, selected


def _objects(repo, oids):
    """Read complete raw objects and recompute Git's content-addressed identity."""
    oids = sorted(oids)
    request = ('\n'.join(oids) + '\n').encode()
    headers = _git(repo, 'cat-file', '--batch-check', data=request).splitlines()
    _require(len(headers) == len(oids), 'object_inventory')
    total = 0
    for oid, header in zip(oids, headers):
        fields = header.split()
        _require(len(fields) == 3 and fields[0].decode() == oid
                 and fields[1] in (b'commit', b'tree', b'blob'), 'missing_object')
        size = int(fields[2])
        total += size
        _require(0 <= size <= MAX_MEMBER and total <= MAX_ARCHIVE, 'object_size')
    out = _git(repo, 'cat-file', '--batch', data=request)
    result, offset = {}, 0
    for oid in oids:
        end = out.find(b'\n', offset)
        header = out[offset:end].split()
        _require(len(header) == 3 and header[0].decode() == oid, 'missing_object')
        kind, size = header[1].decode('ascii'), int(header[2])
        _require(0 <= size <= MAX_MEMBER, 'object_size')
        content = out[end + 1:end + 1 + size]
        _require(len(content) == size and out[end + 1 + size:end + 2 + size] == b'\n',
                 'invalid_object')
        actual = hashlib.sha1((kind + ' ' + str(size)).encode() + b'\0' + content).hexdigest()
        _require(actual == oid, 'object_hash')
        result[oid] = (kind, content)
        offset = end + size + 2
    _require(offset == len(out), 'object_trailing_data')
    return result


def _manifest(source, root, selected, objects, cert):
    entries = []
    for path, (mode, oid) in sorted(selected.items()):
        kind, content = objects[oid]
        _require(kind == 'blob', 'selected_not_blob')
        entries.append(dict(path=path, mode=mode, oid=oid,
                            sha256=_digest(content), size=len(content)))
    return dict(schema='carbonic.source-capsule.v1', source=source, root_tree=root,
                return_cert_sha256=_digest(cert), files=entries,
                objects=[dict(oid=o, type=k, size=len(b))
                         for o, (k, b) in sorted(objects.items())])


def _links(selected, objects):
    links = {}
    for path, (mode, oid) in selected.items():
        if mode != '120000':
            continue
        target = objects[oid][1].decode('utf-8')
        _require(target not in ('', '.', '..') and '/' not in target
                 and '\\' not in target and ':' not in target
                 and all(ord(c) >= 32 for c in target), 'unsafe_symlink')
        sibling = str(PurePosixPath(path).parent / target)
        _require(sibling in selected and selected[sibling][0] in ('100644', '100755'),
                 'unsafe_symlink')
        links[path] = target
    return links


def _index(repo, source, files, selected):
    _git(repo, 'read-tree', source)
    excluded = sorted(set(files) - set(selected))
    if excluded:
        _git(repo, 'update-index', '--skip-worktree', '-z', '--stdin',
             data=b'\0'.join(p.encode() for p in excluded) + b'\0')


def _newrepo(path, source):
    (path / '.git/objects/pack').mkdir(parents=True)
    (path / '.git/refs').mkdir()
    (path / '.git/config').write_bytes(CONFIG)
    (path / '.git/HEAD').write_text(source + '\n')
    (path / '.git/shallow').write_text(source + '\n')


def _openssl(executable):
    _require(_run([executable, 'version']).startswith(b'OpenSSL 3.'), 'openssl_3_required')
    return executable


def _cert(cert, openssl):
    _require(0 < len(cert) <= 65536 and cert.count(b'-----BEGIN CERTIFICATE-----') == 1
             and b'PRIVATE KEY' not in cert, 'invalid_certificate')
    _run([_openssl(openssl), 'x509', '-noout'], data=cert)


def prepare(sourceRepo, full40hexSource, returnCert, outputTar, *, openssl='openssl'):
    """Package only immutable selected blobs, real commit and all tree topology.

    Returns a private manifest augmented with the plaintext capsule digest. Never
    print or publish the returned manifest or output tar in a public workflow.
    """
    source = _hex(full40hexSource, 40)
    repo, output = Path(sourceRepo).resolve(), Path(outputTar).absolute()
    _require(not output.exists() and not output.is_symlink(), 'output_exists')
    cert = Path(returnCert).read_bytes()
    _cert(cert, openssl)
    root, trees, files, selected = _tree(repo, source)
    oids = {source} | trees | {oid for _, oid in selected.values()}
    objects = _objects(repo, oids)
    links = _links(selected, objects)
    manifest = _manifest(source, root, selected, objects, cert)
    with _temporary() as temporary:
        stage = Path(temporary)
        _newrepo(stage, source)
        pack = _git(repo, 'pack-objects', '--stdout', '--no-reuse-delta',
                    data=('\n'.join(sorted(oids)) + '\n').encode())
        _git(stage, 'index-pack', '--no-rev-index', '--stdin', data=pack)
        _index(stage, source, files, selected)
        contents = {'.carbonic/manifest.json': json.dumps(manifest, sort_keys=True).encode() + b'\n',
                    '.carbonic/return.pem': cert}
        for p in (stage / '.git').rglob('*'):
            if p.is_file():
                contents[str(p.relative_to(stage))] = p.read_bytes()
        for path, (_, oid) in selected.items():
            contents[path] = objects[oid][1]
        _require(len(contents) < MAX_ENTRIES and all(len(b) <= MAX_MEMBER for b in contents.values()),
                 'capsule_size')
        # Exclusive creation, private from the first byte; no checkout/filter use.
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, 'wb') as stream:
                with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                    directory = tarfile.TarInfo('.git/refs')
                    directory.type, directory.mode = tarfile.DIRTYPE, 0o700
                    archive.addfile(directory)
                    for path, content in sorted(contents.items()):
                        member = tarfile.TarInfo(path)
                        member.mode = 0o755 if selected.get(path, ('',))[0] == '100755' else 0o644
                        if path in links:
                            member.type, member.linkname = tarfile.SYMTYPE, links[path]
                            archive.addfile(member)
                        else:
                            member.size = len(content)
                            archive.addfile(member, io.BytesIO(content))
            _require(output.stat().st_size <= MAX_ARCHIVE, 'capsule_size')
        except BaseException:
            output.unlink(missing_ok=True)
            raise
    return dict(manifest, capsule_sha256=_digest(output.read_bytes()), capsule_bytes=output.stat().st_size)


def _archive(path):
    _require(path.stat().st_size <= MAX_ARCHIVE, 'archive_size')
    members, total, offset = {}, 0, 0
    with tarfile.open(path, mode='r:') as archive:
        for item in archive:
            name = _path(item.name)
            _require(item.offset == offset and item.offset_data == offset + 512,
                     'archive_extension')
            offset += 512 + ((item.size + 511) // 512) * 512
            _require(name not in members and len(members) < MAX_ENTRIES, 'duplicate_or_entry_limit')
            _require(item.isreg() or item.issym() or item.isdir(), 'archive_type')
            _require(not item.pax_headers and (not item.isreg() or not item.linkname), 'archive_metadata')
            _require(0 <= item.size <= MAX_MEMBER, 'member_size')
            total += item.size
            _require(total <= MAX_ARCHIVE, 'archive_size')
            if item.isdir():
                _require(item.size == 0, 'directory_size')
                data = b''
            elif item.issym():
                _require(item.size == 0 and not name.startswith(('.git/', '.carbonic/')), 'metadata_symlink')
                data = item.linkname.encode('utf-8')
            else:
                data = archive.extractfile(item).read(MAX_MEMBER + 1)
                _require(len(data) == item.size, 'member_size')
            _require(item.mode in (0o600, 0o644, 0o700, 0o755, 0o777)
                     and not item.mode & 0o7000, 'archive_mode')
            members[name] = (item, data)
    with path.open('rb') as stream:
        stream.seek(offset)
        trailer = stream.read()
    _require(len(trailer) >= 1024 and not any(trailer), 'archive_trailing_data')
    _require(len({p.casefold() for p in members}) == len(members), 'path_collision')
    for path in members:
        for parent in PurePosixPath(path).parents:
            if str(parent) in members:
                _require(members[str(parent)][0].isdir(), 'parent_not_directory')
    return members


def verify_extract(tar, expectedSHA256, expectedSource, freshDestination, *, openssl='openssl'):
    """Verify everything in a private staging directory, then promote atomically.

    freshDestination must not exist. The expected plaintext digest/source must
    originate from the trusted dispatch, not an untrusted manifest or filename.
    """
    digest, source = _hex(expectedSHA256, 64), _hex(expectedSource, 40)
    path, destination = Path(tar), Path(freshDestination).absolute()
    _require(not destination.exists() and not destination.is_symlink(), 'destination_exists')
    _require(path.stat().st_size <= MAX_ARCHIVE, 'archive_size')
    _require(_digest(path.read_bytes()) == digest, 'capsule_hash')
    members = _archive(path)
    # Before running Git, constrain all its configuration and auxiliary files.
    gitfiles = {'.git/HEAD', '.git/config', '.git/shallow', '.git/index'}
    packs = {n for n in members if re.fullmatch(r'\.git/objects/pack/pack-[0-9a-f]{40}\.(pack|idx)', n)}
    _require(len(packs) == 2 and len({n.rsplit('.', 1)[0] for n in packs}) == 1, 'pack_inventory')
    allowedfiles = gitfiles | packs | METADATA
    for name, (item, _) in members.items():
        if item.isdir():
            _require(name == '.git/refs' or any(p.startswith(name + '/') for p in members),
                     'unexpected_directory')
        else:
            _require(name in allowedfiles or _selected(name), 'unexpected_file')
            if name.startswith(('.git/', '.carbonic/')):
                _require(name in allowedfiles and item.isreg(), 'unsafe_metadata')
    _require(all(n in members and members[n][0].isreg() for n in allowedfiles), 'missing_metadata')
    _require('.git/refs' in members and members['.git/refs'][0].isdir(), 'missing_refs')
    _require(members['.git/config'][1] == CONFIG, 'unsafe_git_config')
    _require(members['.git/HEAD'][1] == (source + '\n').encode()
             and members['.git/shallow'][1] == (source + '\n').encode(), 'source_identity')
    cert = members['.carbonic/return.pem'][1]
    _cert(cert, openssl)
    manifest = json.loads(members['.carbonic/manifest.json'][1])
    with _temporary(destination.parent) as temporary:
        stage = Path(temporary) / 'verified'
        stage.mkdir(mode=0o700)
        for name, (item, content) in members.items():
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if item.isdir():
                target.mkdir(exist_ok=True, mode=0o700)
            elif not item.issym():
                target.write_bytes(content)
                target.chmod(0o755 if item.mode == 0o755 else 0o600)
        _git(stage, 'verify-pack', str(stage / next(n for n in packs if n.endswith('.idx'))))
        inventory = _git(stage, 'cat-file', '--batch-all-objects', '--batch-check=%(objectname)').decode().splitlines()
        _require(len(inventory) <= MAX_ENTRIES and len(set(inventory)) == len(inventory), 'object_inventory')
        objects = _objects(stage, inventory)
        root, trees, files, selected = _tree(stage, source)
        expectedoids = {source} | trees | {o for _, o in selected.values()}
        _require(set(objects) == expectedoids, 'object_coverage')
        _require(all(objects[o][0] == 'tree' for o in trees)
                 and objects[source][0] == 'commit', 'object_types')
        expected = _manifest(source, root, selected, objects, cert)
        _require(manifest == expected, 'manifest_coverage')
        _require({n for n, (i, _) in members.items() if not i.isdir()} == allowedfiles | set(selected),
                 'file_coverage')
        links = _links(selected, objects)
        for name, (mode, oid) in selected.items():
            item, content = members[name]
            _require(item.issym() == (mode == '120000') and content == objects[oid][1], 'working_file_parity')
            _require(mode == '120000' or item.mode == (0o755 if mode == '100755' else 0o644), 'working_file_mode')
            if name in links:
                (stage / name).symlink_to(links[name])
        # Validate supplied index against an independently regenerated index,
        # including every excluded entry's skip-worktree bit. Binary timestamps
        # and stat cache are deliberately not trusted as content evidence.
        actual = _git(stage, 'ls-files', '--stage', '-z')
        flags = _git(stage, 'ls-files', '-v', '-z')
        (stage / '.git/index').unlink()
        _index(stage, source, files, selected)
        _require(actual == _git(stage, 'ls-files', '--stage', '-z')
                 and flags == _git(stage, 'ls-files', '-v', '-z'), 'index_parity')
        _require(_git(stage, 'rev-parse', 'HEAD').strip().decode() == source, 'source_identity')
        _require(not _git(stage, 'status', '--porcelain', '--untracked-files=no', '--', *ALLOWLIST), 'scoped_status')
        _git(stage, 'diff', '--exit-code', '--', *PARITY_SCOPES)
        os.rename(stage, destination)
    return dict(source=source, capsule_sha256=digest, files=len(selected),
                objects=len(objects), root_tree=root, return_cert_sha256=_digest(cert))


def keygen(privateDirectory, *, openssl='openssl'):
    """Create a fresh private directory and ephemeral RSA-3072 return keypair."""
    directory = Path(privateDirectory).absolute()
    directory.mkdir(mode=0o700)
    key, cert = directory / 'recipient.key', directory / 'recipient.pem'
    try:
        # OpenSSL creates keys according to umask; precreate privately so even
        # a permissive caller umask cannot briefly expose key material.
        key.touch(mode=0o600, exist_ok=False)
        _run([_openssl(openssl), 'req', '-x509', '-newkey', 'rsa:3072', '-noenc',
              '-sha256', '-days', '1', '-subj', '/CN=carbonic-ephemeral',
              '-keyout', str(key), '-out', str(cert)])
        key.chmod(0o600)
        cert.chmod(0o600)
    except BaseException:
        shutil.rmtree(directory)
        raise
    return dict(private_key=str(key), certificate=str(cert), certificate_sha256=_digest(cert.read_bytes()))


def _pending(output):
    output = Path(output).absolute()
    _require(not output.exists() and not output.is_symlink(), 'output_exists')
    fd, pending = tempfile.mkstemp(prefix='.cms-pending-', dir=output.parent)
    os.close(fd)
    return output, Path(pending)


def encrypt(plaintext, certificate, output, *, openssl='openssl'):
    _cert(Path(certificate).read_bytes(), openssl)
    destination, pending = _pending(output)
    try:
        _run([openssl, 'cms', '-encrypt', '-binary', '-aes-256-gcm', '-in',
              str(Path(plaintext).absolute()), '-outform', 'DER', '-out', str(pending),
              str(Path(certificate).absolute())])
        _require(pending.stat().st_size > 0, 'empty_ciphertext')
        os.link(pending, destination)
    finally:
        pending.unlink(missing_ok=True)
    return dict(sha256=_digest(destination.read_bytes()), bytes=destination.stat().st_size)


def decrypt(ciphertext, certificate, privateKey, output, expectedSHA256=None, *, openssl='openssl'):
    _openssl(openssl)
    if expectedSHA256 is not None:
        _hex(expectedSHA256, 64)
    _require(Path(privateKey).stat().st_mode & 0o777 == 0o600, 'private_key_permissions')
    destination, pending = _pending(output)
    try:
        _run([openssl, 'cms', '-decrypt', '-binary', '-inform', 'DER', '-in',
              str(Path(ciphertext).absolute()), '-recip', str(Path(certificate).absolute()),
              '-inkey', str(Path(privateKey).absolute()), '-out', str(pending)])
        digest = _digest(pending.read_bytes())
        _require(expectedSHA256 is None or digest == expectedSHA256, 'plaintext_hash')
        os.link(pending, destination)
    finally:
        pending.unlink(missing_ok=True)
    return dict(sha256=digest, bytes=destination.stat().st_size)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openssl', default='openssl')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare')
    for flag in ('source-repo', 'source', 'return-cert', 'output'):
        p.add_argument('--' + flag, required=True)
    p = sub.add_parser('verify')
    for flag in ('capsule', 'expected-sha256', 'expected-source', 'destination'):
        p.add_argument('--' + flag, required=True)
    p = sub.add_parser('keygen')
    p.add_argument('--directory', required=True)
    for command in ('encrypt', 'decrypt'):
        p = sub.add_parser(command)
        for flag in ('input', 'certificate', 'output'):
            p.add_argument('--' + flag, required=True)
        if command == 'decrypt':
            p.add_argument('--private-key', required=True)
            p.add_argument('--expected-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'prepare':
            result = prepare(args.source_repo, args.source, args.return_cert, args.output, openssl=args.openssl)
            result = {k: result[k] for k in ('source', 'capsule_sha256', 'capsule_bytes', 'return_cert_sha256')}
        elif args.command == 'verify':
            result = verify_extract(args.capsule, args.expected_sha256, args.expected_source,
                                    args.destination, openssl=args.openssl)
        elif args.command == 'keygen':
            result = keygen(args.directory, openssl=args.openssl)
            result = {'certificate_sha256': result['certificate_sha256']}
        elif args.command == 'encrypt':
            result = encrypt(args.input, args.certificate, args.output, openssl=args.openssl)
        else:
            result = decrypt(args.input, args.certificate, args.private_key, args.output,
                             args.expected_sha256, openssl=args.openssl)
        print(json.dumps(dict(status='ok', **result), sort_keys=True))
        return 0
    except (CapsuleError, OSError, ValueError, tarfile.TarError, UnicodeError) as exc:
        code = str(exc) if isinstance(exc, CapsuleError) else 'invalid_input'
        print(json.dumps(dict(status='error', code=code)))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
