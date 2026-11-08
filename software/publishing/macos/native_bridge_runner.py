"""Hosted exact-source CMS bridge. Public output is fixed stage codes.

Keep this and capsule.py at software/publishing/macos/ in the public checkout.
Production invokes only the fixed exact-source pipeline in native_production.py.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import capsule

MAX_PAYLOAD = 128 * 1024 * 1024
MAX_JSON = 64 * 1024
MAIN = b'#include <stdio.h>\nint main(void) { puts("native fixture ok"); return 0; }\n'
FIXTURE = 'software/publishing/macos/fixture/'
FIELDS = ('repository', 'workflow_ref', 'head_sha', 'run_id', 'attempt', 'nonce',
          'source', 'capsule_sha256', 'return_cert_sha256')
NATIVE_STEPS = ('compile_arm64', 'compile_x86_64', 'lipo', 'lipo_verify',
                'sign', 'verify_signature', 'runtime_arm64', 'runtime_x86_64')
PROBE_NAMES = ('host_arch', 'xcode', 'os', 'clang')
EVIDENCE_NAMES = {n + '.log' for n in (*NATIVE_STEPS, 'host_arch', 'xcode', 'os',
                                      'clang', 'deliberate_failure')} | {
    'private-diagnostic.txt', 'result.json'}
PRODUCT_NAMES = {'arm64', 'x86_64', 'fixture', 'fixture.zip', 'manifest.json', 'fixture.rb'}


class BridgeError(ValueError):
    """Internal errors must never be printed verbatim by an entry point."""


def require(condition, code='protocol'):
    if not condition:
        raise BridgeError(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hexval(value, size):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % size, value), 'hex')
    return value


def integer(value):
    require(isinstance(value, (str, int)) and not isinstance(value, bool)
            and re.fullmatch('[1-9][0-9]{0,18}', str(value)), 'integer')
    return int(value)


def inputs(env):
    mode = env.get('BRIDGE_MODE')
    require(mode in ('fixture', 'production'), 'mode')
    repo = env.get('GITHUB_REPOSITORY', '')
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo), 'repository')
    ref = env.get('GITHUB_WORKFLOW_REF', '')
    require(ref.startswith(repo + '/.github/workflows/')
            and re.fullmatch(r'[A-Za-z0-9_./@-]+', ref)
            and '@refs/heads/' in ref, 'workflow')
    nonce = env.get('BRIDGE_NONCE', '')
    require(re.fullmatch(r'(?:[0-9a-f]{32}|[0-9a-f]{64})', nonce), 'nonce')
    require(env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'event')
    require(env.get('BRIDGE_FAIL') in ('true', 'false'), 'boolean')
    result = dict(repository=repo, workflow_ref=ref,
                  head_sha=hexval(env.get('GITHUB_SHA'), 40),
                  run_id=integer(env.get('GITHUB_RUN_ID')),
                  attempt=integer(env.get('GITHUB_RUN_ATTEMPT')), nonce=nonce,
                  source=hexval(env.get('BRIDGE_SOURCE'), 40),
                  capsule_sha256=hexval(env.get('BRIDGE_CAPSULE_SHA256'), 64),
                  return_cert_sha256=hexval(env.get('BRIDGE_RETURN_CERT_SHA256'), 64),
                  draft_release_id=integer(env.get('BRIDGE_DRAFT_ID')),
                  fail_fixture=env['BRIDGE_FAIL'] == 'true')
    require(result['attempt'] == 1, 'rerun_refused')
    if mode == 'production':
        import native_production as production
        require(result['source'] == production.SOURCE and not result['fail_fixture'], 'production_source')
        result.update(mode='production', wrapper_sha256=hexval(env.get('BRIDGE_WRAPPER_SHA256'), 64),
                      workflow_sha256=hexval(env.get('BRIDGE_WORKFLOW_SHA256'), 64))
    return result


def identity_fields(config):
    return FIELDS + (('mode', 'wrapper_sha256', 'workflow_sha256') if config.get('mode') == 'production' else ())


def schema(config, phase):
    return 'native-' + ('production' if config.get('mode') == 'production' else 'fixture') + '.' + phase + '.v1'


def return_policy(config):
    if config.get('mode') == 'production':
        import native_production as production
        return production.MAX_RETURN, production.MAX_MEMBER, production.EVIDENCE | {n + '.log' for n in PROBE_NAMES}, production.PRODUCTS
    return MAX_PAYLOAD, MAX_PAYLOAD, EVIDENCE_NAMES, PRODUCT_NAMES


def binding(actual, expected):
    require(all(type(actual.get(k)) is type(expected[k]) and actual.get(k) == expected[k]
                for k in identity_fields(expected)), 'binding')


def parse_public_identity(raw, config, phase):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'public_identity')
            value[key] = item
        return value
    return public_identity(json.loads(raw, object_pairs_hook=unique), config, phase)


def public_identity(value, config, phase):
    """Exact public wire schemas; private diagnostics belong only in ciphertext."""
    require(type(value) is dict and phase in ('recipient', 'return'), 'public_identity')
    extra = ({'recipient_cert_sha256', 'tools'} if phase == 'recipient' else
             {'outcome', 'toolsummary', 'plaintext_sha256', 'plaintext_bytes',
              'ciphertext_sha256', 'ciphertext_bytes'})
    require(set(value) == set(identity_fields(config)) | {'schema'} | extra,
            'public_identity')
    binding(value, config)
    require(value['schema'] == schema(config, phase), 'public_identity')
    if phase == 'recipient':
        hexval(value['recipient_cert_sha256'], 64)
        tools = value['tools']
        require(type(tools) is dict, 'public_tools')
        if config.get('mode') == 'production':
            require(set(tools) == {'openssl_3'} and tools['openssl_3'] is True, 'public_tools')
        else:
            require(set(tools) == {'openssl', 'python', *PROBE_NAMES}, 'public_tools')
            require(type(tools['openssl']) is str and len(tools['openssl']) <= 1024
                    and tools['openssl'].startswith('OpenSSL 3.') and '\n' not in tools['openssl']
                    and type(tools['python']) is str
                    and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*', tools['python']), 'public_tools')
            for name in PROBE_NAMES:
                require(type(tools[name]) is dict and set(tools[name]) == {'exit'}
                        and type(tools[name]['exit']) is int and -255 <= tools[name]['exit'] <= 255,
                        'public_tools')
    else:
        require(type(value['outcome']) is str and value['outcome'] in ('success', 'failure'), 'public_identity')
        summary = value['toolsummary']
        require(type(summary) is dict and set(summary) == {'openssl_3', 'native_failed'}
                and summary['openssl_3'] is True and type(summary['native_failed']) is bool
                and (value['outcome'] == 'failure' or summary['native_failed'] is False), 'public_tools')
        cap = return_policy(config)[0]
        for prefix in ('plaintext', 'ciphertext'):
            hexval(value[prefix + '_sha256'], 64)
            require(type(value[prefix + '_bytes']) is int and 0 < value[prefix + '_bytes'] <= cap,
                    'public_identity')
    return value


def write_json(path, value):
    raw = json.dumps(value, sort_keys=True).encode() + b'\n'
    require(len(raw) <= MAX_JSON, 'json_size')
    path = Path(path)
    pending = path.with_name(path.name + '.pending')
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    os.replace(pending, path)


def read_json(path):
    data = Path(path).read_bytes()
    require(len(data) <= MAX_JSON, 'json_size')
    value = json.loads(data)
    require(isinstance(value, dict), 'json_shape')
    return value


def build_env(root, original=None):
    """An allowlist, not a token-name denylist. All children lose Actions auth."""
    original = os.environ if original is None else original
    root = Path(root).resolve()
    env = {'PATH': original.get('PATH', os.defpath), 'LC_ALL': 'C',
           **({'HOME': original['HOME']} if 'HOME' in original else {}),
           'TMPDIR': str(root / 'tmp'),
           'TMP': str(root / 'tmp'), 'TEMP': str(root / 'tmp'),
           'XDG_CACHE_HOME': str(root / 'cache'),
           'HOMEBREW_CACHE': str(root / 'brew-cache'),
           'HOMEBREW_LOGS': str(root / 'brew-logs'),
           'HOMEBREW_TEMP': str(root / 'tmp'), 'HOMEBREW_NO_AUTO_UPDATE': '1',
           'HOMEBREW_NO_ANALYTICS': '1', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_SYSTEM': os.devnull,
           'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_TERMINAL_PROMPT': '0',
           'PUB_CACHE': str(root / 'pub-cache'), 'CMAKE_BUILD_PARALLEL_LEVEL': '2',
           'FLUTTER_SUPPRESS_ANALYTICS': 'true', 'CI': 'true'}
    if (root / 'sdk/flutter/bin/flutter').is_file():
        env['PATH'] = str(root / 'sdk/flutter/bin') + os.pathsep + env['PATH']
    for key in ('TMPDIR', 'XDG_CACHE_HOME', 'HOMEBREW_CACHE', 'HOMEBREW_LOGS'):
        Path(env[key]).mkdir(mode=0o700, parents=True, exist_ok=True)
    return env


def capture(argv, root, name, *, cwd=None, timeout=180, process_group=False):
    """Every native stdout/stderr byte stays in an explicit private file."""
    log = root / 'evidence' / (name + '.log')
    with log.open('xb') as stream:
        try:
            if process_group:
                return private_process(argv, root, stream, cwd=cwd, timeout=timeout)
            proc = subprocess.run(argv, cwd=cwd, env=build_env(root), stdout=stream,
                                  stderr=subprocess.STDOUT, timeout=timeout, check=False)
            return proc.returncode
        except (OSError, subprocess.TimeoutExpired):
            stream.write(b'private command unavailable or timed out\n')
            return 125


def private_process(argv, root, stdout, *, stderr=subprocess.STDOUT, cwd=None, timeout=600):
    """Bound a production process group so timed-out grandchildren cannot linger."""
    proc = subprocess.Popen(argv, cwd=cwd, env=build_env(root), stdout=stdout,
                            stderr=stderr, start_new_session=True)
    try:
        return proc.wait(timeout=timeout)
    finally:
        # Even a nominally successful parent must not leave build children alive.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)


def openssl3(root):
    env = build_env(root)
    try:
        p = subprocess.run(['brew', '--prefix', 'openssl@3'], env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        require(p.returncode == 0 and len(p.stdout) < 4096, 'openssl_prefix')
        binary = Path(p.stdout.decode().strip()) / 'bin/openssl'
        p = subprocess.run([str(binary), 'version'], env=env, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=10)
        require(p.returncode == 0 and p.stdout.startswith(b'OpenSSL 3.')
                and len(p.stdout) < 1024, 'openssl_3')
        return str(binary), p.stdout.decode().strip()
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        raise BridgeError('openssl_3') from exc


def layout(config, workspace):
    workspace = Path(workspace).resolve()
    root = workspace / 'build/native-bridge' / (
        f"{config['run_id']}-{config['attempt']}-{config['nonce']}")
    return root


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def asset_host(url):
    p = urllib.parse.urlsplit(url)
    host = p.hostname or ''
    require(p.scheme == 'https' and p.port in (None, 443) and not p.username
            and not p.password and not p.fragment
            and (host in ('api.github.com', 'release-assets.githubusercontent.com',
                          'objects.githubusercontent.com', 'github.com')
                 or host.endswith('.githubusercontent.com')), 'download_host')
    return host


class GitHub:
    """Bearer is used only on api.github.com; redirects explicitly drop it."""
    def __init__(self, token, opener=None):
        require(bool(token), 'token_unavailable')
        self.token = token
        self.opener = opener or urllib.request.build_opener(NoRedirect())

    def fetch(self, url, *, limit, binary=False):
        for redirect in range(4):
            host = asset_host(url)
            headers = {'Accept': 'application/octet-stream' if binary else 'application/vnd.github+json',
                       'User-Agent': 'native-fixture-bridge', 'X-GitHub-Api-Version': '2022-11-28'}
            if host == 'api.github.com':
                headers['Authorization'] = 'Bearer ' + self.token
            request = urllib.request.Request(url, headers=headers)
            try:
                response = self.opener.open(request, timeout=20)
            except urllib.error.HTTPError as exc:
                if exc.code in (301, 302, 303, 307, 308):
                    location = exc.headers.get('Location', '')
                    exc.close()
                    require(binary and redirect < 3, 'redirect')
                    url = urllib.parse.urljoin(url, location)
                    # Do not allow a signed-asset redirect to return to the API.
                    require(asset_host(url) != 'api.github.com', 'redirect_api')
                    continue
                status = exc.code
                exc.close()
                raise BridgeError('http_' + str(status)) from None
            except (OSError, urllib.error.URLError) as exc:
                raise BridgeError('http_transport') from exc
            with response:
                require(response.status == 200, 'http_status')
                size = response.headers.get('Content-Length')
                if size is not None:
                    require(size.isdigit() and int(size) <= limit, 'http_size')
                content = response.read(limit + 1)
                require(len(content) <= limit, 'http_size')
                return content
        raise BridgeError('redirect')

    def json(self, endpoint):
        raw = self.fetch('https://api.github.com/' + endpoint, limit=MAX_JSON)
        return json.loads(raw)


def select_asset(assets, config):
    require(isinstance(assets, list) and len(assets) <= 100, 'asset_inventory')
    name = 'capsule-' + config['nonce'] + '.cms'
    require(all(isinstance(a, dict) for a in assets), 'asset_inventory')
    matches = [a for a in assets if a.get('name') == name]
    require(len(matches) <= 1, 'duplicate_asset')
    # This dedicated transport release must contain nothing else.
    require(len(assets) == len(matches), 'unexpected_asset')
    if not matches:
        return None
    a = matches[0]
    integer(a.get('id'))
    require(a.get('state') == 'uploaded' and type(a.get('size')) is int
            and 0 < a['size'] <= MAX_PAYLOAD, 'asset_size_state')
    if a.get('digest') is not None:
        require(re.fullmatch(r'sha256:[0-9a-f]{64}', a['digest']), 'asset_digest')
    return a


def receive(root, config, api, *, seconds=600, sleep=time.sleep, monotonic=time.monotonic):
    end = monotonic() + min(seconds, 600)
    endpoint = f"repos/{config['repository']}/releases/{config['draft_release_id']}"
    while True:
        release = api.json(endpoint)
        require(release.get('id') == config['draft_release_id'] and release.get('draft') is True
                and release.get('tag_name') == 'native-bridge-' + config['nonce'], 'draft_binding')
        # Paginated asset endpoint, not release.assets (which can be truncated).
        assets = api.json(endpoint + '/assets?per_page=100')
        require(len(assets) < 100, 'asset_inventory')
        asset = select_asset(assets, config)
        if asset:
            raw = api.fetch(f"https://api.github.com/repos/{config['repository']}/releases/assets/{asset['id']}",
                            limit=MAX_PAYLOAD, binary=True)
            require(len(raw) == asset['size'] and len(raw) > 0, 'asset_size')
            if asset.get('digest'):
                require('sha256:' + digest(raw) == asset['digest'], 'asset_hash')
            path = root / 'capsule.cms'
            with path.open('xb') as stream:
                stream.write(raw)
            return path
        require(monotonic() < end, 'capsule_timeout')
        sleep(min(5, max(0, end - monotonic())))


def fixture_source(source):
    manifest = read_json(source / '.carbonic/manifest.json')
    expected = {'.gitignore', FIXTURE + 'main.c', FIXTURE + 'private-canary.txt'}
    require({f['path'] for f in manifest['files']} == expected, 'fixture_inventory')
    require(all(f['mode'] == '100644' for f in manifest['files']), 'fixture_mode')
    require((source / (FIXTURE + 'main.c')).read_bytes() == MAIN, 'fixture_source')
    require((source / '.gitignore').read_bytes() == b'build/\n', 'fixture_source')
    canary = (source / (FIXTURE + 'private-canary.txt')).read_text()
    require(re.fullmatch(r'PRIVATE-FIXTURE-[0-9a-f]{64}\n', canary), 'fixture_canary')
    return canary


def native_fixture(root, source, config):
    canary = fixture_source(source)
    (root / 'evidence/private-diagnostic.txt').write_text(canary)
    main = str(source / (FIXTURE + 'main.c'))
    products = root / 'products'
    products.mkdir(mode=0o700)
    arm, intel, fat = [str(products / n) for n in ('arm64', 'x86_64', 'fixture')]
    cmds = [
        ('compile_arm64', ['xcrun', 'clang', '-arch', 'arm64', '-Werror', main, '-o', arm]),
        ('compile_x86_64', ['xcrun', 'clang', '-arch', 'x86_64', '-Werror', main, '-o', intel]),
        ('lipo', ['xcrun', 'lipo', '-create', arm, intel, '-output', fat]),
        ('lipo_verify', ['xcrun', 'lipo', fat, '-verify_arch', 'arm64', 'x86_64']),
        ('sign', ['codesign', '--force', '--sign', '-', fat]),
        ('verify_signature', ['codesign', '--verify', '--strict', '--verbose=2', fat]),
        ('runtime_arm64', ['arch', '-arm64', fat]),
        ('runtime_x86_64', ['arch', '-x86_64', fat])]
    results = {name: capture(cmd, root, name, cwd=products) for name, cmd in cmds}
    # Deliberate native failure must survive sealing/upload and job cleanup.
    if config['fail_fixture']:
        results['deliberate_failure'] = capture(
            ['xcrun', 'clang', '-arch', 'arm64', '-Werror', '-x', 'c', '/dev/null',
             '-o', str(products / 'must-not-exist')], root, 'deliberate_failure')
        require(results['deliberate_failure'] != 0, 'negative_fixture_not_failed')
        with (root / 'evidence/deliberate_failure.log').open('ab') as stream:
            stream.write(canary.encode())
    # The production-like payload is also encrypted; host inspects ZIP members.
    with zipfile.ZipFile(products / 'fixture.zip', 'w') as archive:
        if Path(fat).is_file():
            archive.write(fat, 'fixture')
        if config['fail_fixture']:
            archive.writestr('unexpected-private-member.txt', canary)
    (products / 'manifest.json').write_text(json.dumps({'fixture': True}))
    (products / 'fixture.rb').write_text('# nonsensitive fixture, not a publishable cask\n')
    return results


def seal(root, config, openssl, result):
    """Explicit returned paths: never archive source, keys, or the private root."""
    cert = root / 'source/.carbonic/return.pem'
    require(cert.is_file() and digest(cert.read_bytes()) == config['return_cert_sha256'], 'return_cert')
    cap, member_cap, evidence_names, product_names = return_policy(config)
    outputs = {}
    total = 0
    for folder in ('evidence', 'products'):
        directory = root / folder
        if directory.exists():
            for path in sorted(directory.iterdir()):
                require(path.is_file() and not path.is_symlink()
                        and path.stat().st_size <= member_cap, 'return_inventory')
                require(path.name in (evidence_names if folder == 'evidence' else product_names),
                        'return_inventory')
                require(path.name != 'result.json', 'result_exists')
                total += path.stat().st_size
                require(total <= cap and len(outputs) < 64, 'return_size')
                outputs[folder + '/' + path.name] = dict(
                    sha256=digest(path.read_bytes()), bytes=path.stat().st_size)
    result['outputs'] = outputs
    write_json(root / 'evidence/result.json', result)
    archive_path = root / 'return.tar'
    with tarfile.open(archive_path, 'x', format=tarfile.USTAR_FORMAT) as archive:
        for folder in ('evidence', 'products'):
            directory = root / folder
            if directory.exists():
                for path in sorted(directory.iterdir()):
                    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= member_cap,
                            'return_inventory')
                    archive.add(path, arcname=folder + '/' + path.name, recursive=False)
    require(0 < archive_path.stat().st_size <= cap, 'return_size')
    plain_hash = digest(archive_path.read_bytes())
    output = root / 'public-return'
    output.mkdir(mode=0o700)
    cms = output / 'encrypted-return.cms'
    encrypted = capsule.encrypt(archive_path, cert, cms, openssl=openssl)
    require(cms.is_file() and 0 < cms.stat().st_size <= cap
            and cms.stat().st_size == encrypted['bytes'], 'seal_failed')
    identity = {k: config[k] for k in identity_fields(config)}
    identity.update(schema=schema(config, 'return'), outcome=result['outcome'],
                    toolsummary=dict(openssl_3=True, native_failed=result['native_failed']),
                    plaintext_sha256=plain_hash, plaintext_bytes=archive_path.stat().st_size,
                    ciphertext_sha256=encrypted['sha256'], ciphertext_bytes=encrypted['bytes'])
    public_identity(identity, config, 'return')
    write_json(output / 'identity.json', identity)
    archive_path.unlink()
    return identity


def initialize(root, config):
    if config.get('mode') == 'production':
        import native_production as production
        actual = production.wrapper_identity(Path(__file__).parent,
            Path(os.environ['GITHUB_WORKSPACE']) / '.github/workflows/native-capsule.yml')
        require(all(actual[k] == config[k] for k in actual), 'wrapper_identity')
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(root, 0o700)
    (root / 'evidence').mkdir(mode=0o700)
    openssl, version = openssl3(root)
    if config.get('mode') == 'production':
        (root / 'evidence/openssl.log').write_text(version + '\n')
    # capsule's subprocess environment must point at this job-local project.
    capsule.PROJECT = root
    keys = capsule.keygen(root / 'recipient', openssl=openssl)
    public = root / 'public-recipient'
    public.mkdir(mode=0o700)
    shutil.copyfile(keys['certificate'], public / 'recipient.pem')
    tools = {'openssl': version, 'python': sys.version.split()[0]}
    probes = {}
    for name, command in [('host_arch', ['uname', '-m']), ('xcode', ['xcodebuild', '-version']),
                          ('os', ['sw_vers']), ('clang', ['xcrun', 'clang', '--version'])]:
        code = capture(command, root, name)
        tools[name] = {'exit': code}
        probes[name] = code
    identity = {k: config[k] for k in identity_fields(config)}
    identity.update(schema=schema(config, 'recipient'),
                    recipient_cert_sha256=keys['certificate_sha256'],
                    tools=({'openssl_3': True} if config.get('mode') == 'production' else tools))
    public_identity(identity, config, 'recipient')
    write_json(public / 'identity.json', identity)
    write_json(root / 'private-state.json', dict(config=config, openssl=openssl, probes=probes))


def execute(root, config, api):
    state = read_json(root / 'private-state.json')
    require(state['config'] == config, 'state_binding')
    openssl = state['openssl']
    capsule.PROJECT = root
    result = {k: config[k] for k in identity_fields(config)}
    result.update(schema=schema(config, 'result'), outcome='failure', native={}, protocol='failure',
                  native_failed=True, probes=state.get('probes', {}))
    source = root / 'source'
    key = root / 'recipient/recipient.key'
    try:
        try:
            encrypted = receive(root, config, api)
        except BridgeError as exc:
            if str(exc) == 'http_403':
                print('NATIVE_FIXTURE_RECEIVE_HTTP_403')
            elif str(exc) == 'http_404':
                print('NATIVE_FIXTURE_RECEIVE_HTTP_404')
            raise
        tar = root / 'capsule.tar'
        capsule.decrypt(encrypted, root / 'recipient/recipient.pem', key, tar,
                        config['capsule_sha256'], openssl=openssl)
        capsule.verify_extract(tar, config['capsule_sha256'], config['source'], source, openssl=openssl)
        require(digest((source / '.carbonic/return.pem').read_bytes()) == config['return_cert_sha256'],
                'return_cert')
        # No source execution while recipient decrypt key exists.
        key.unlink()
        encrypted.unlink()
        tar.unlink()
        require(set(result['probes']) == set(PROBE_NAMES)
                and all(type(c) is int for c in result['probes'].values()), 'probe_inventory')
        if config.get('mode') == 'production':
            import native_production as production
            result['native'] = production.native(root, source, dict(config, openssl=openssl))
        else:
            result['native'] = native_fixture(root, source, config)
        result['protocol'] = 'ok'
        result['native_failed'] = any(v != 0 for v in result['native'].values())
        probes_ok = all(c == 0 for c in result['probes'].values()) and all(
            (root / 'evidence' / (n + '.log')).is_file()
            and (root / 'evidence' / (n + '.log')).read_bytes().strip() for n in PROBE_NAMES)
        result['outcome'] = 'success' if not result['native_failed'] and probes_ok else 'failure'
    except (BridgeError, capsule.CapsuleError, OSError, ValueError, tarfile.TarError):
        # Fixed public code only. Never include exception text in public/returned identities.
        result['protocol'] = 'failure'
    finally:
        key.unlink(missing_ok=True)
        (root / 'capsule.cms').unlink(missing_ok=True)
        (root / 'capsule.tar').unlink(missing_ok=True)
    # A validated return certificate may be available even after a native failure.
    seal(root, config, openssl, result)
    if os.environ.get('GITHUB_OUTPUT'):
        # Set only after both ciphertext and its bound identity were committed.
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('sealed=true\n')
    return 0 if result['outcome'] == 'success' else 1


# Exact owned private paths under the job root removed by the always() cleanup step.
# Public certificate/ciphertext outputs (public-recipient, public-return) stay.
# Production xcodebuild writes raw result bundles beside the Debug workspaces.
PRIVATE_DIRECTORIES = ('source', 'recipient', 'products', 'evidence', 'tmp',
                       'cache', 'brew-cache', 'brew-logs', 'design-r5', 'sdk', 'pub-cache',
                       'debug-arm64', 'debug-x86_64',
                       'runtime-arm64.xcresult', 'runtime-x86_64.xcresult')
PRIVATE_FILES = ('capsule.tar', 'capsule.cms', 'return.tar', 'private-state.json',
                 'sdk-version.json', 'reconstruct.tar')
# capsule.verify_extract stages in <root>/capsule-* and capsule.decrypt writes
# <root>/.cms-pending-*; both normally self-delete but survive a hard kill.
PRIVATE_TEMP_PREFIXES = ('capsule-', '.cms-pending-')


def cleanup(root):
    """Best-effort ordinary deletion of owned private paths directly in root."""
    for name in PRIVATE_DIRECTORIES:
        shutil.rmtree(root / name, ignore_errors=True)
    for name in PRIVATE_FILES:
        (root / name).unlink(missing_ok=True)
    try:
        entries = list(root.iterdir()) if root.is_dir() and not root.is_symlink() else []
    except OSError:
        entries = []
    for entry in entries:
        if not entry.name.startswith(PRIVATE_TEMP_PREFIXES):
            continue
        try:
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink(missing_ok=True)
        except OSError:
            pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('init', 'execute', 'cleanup'))
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        config = inputs(os.environ)
        root = layout(config, os.environ['GITHUB_WORKSPACE'])
        if args.phase == 'cleanup':
            cleanup(root)
            code = 0
        elif args.phase == 'init':
            initialize(root, config)
            code = 0
        else:
            token = os.environ.pop('GH_TOKEN', '')
            os.environ.pop('GITHUB_TOKEN', None)
            code = execute(root, config, GitHub(token))
        prefix = 'NATIVE_PRODUCTION' if config.get('mode') == 'production' else 'NATIVE_FIXTURE'
        print(prefix + ('_OK' if code == 0 else '_FAILED'))
        return code
    except Exception:
        # Final boundary also suppresses unexpected tracebacks from dependencies.
        print('NATIVE_PRODUCTION_PROTOCOL_FAILED' if os.environ.get('BRIDGE_MODE') == 'production'
              else 'NATIVE_FIXTURE_PROTOCOL_FAILED')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
