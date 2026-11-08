"""Local controller for hosted fixtures and exact-source encrypted production.

Uses the user's existing gh login without reading/exporting its token. Receipt
and return keys are private, local-only, and must stay under this project's build.
No command here is run implicitly on import or by unit tests.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import io
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import subprocess
import tarfile
import time
import zipfile

import capsule
import native_bridge_runner as protocol

require = protocol.require
BridgeError = protocol.BridgeError
PROJECT = Path(__file__).resolve().parents[3]
BINDING = protocol.FIELDS


# GitHub listings/contents grow with history (one run object is ~13 KiB and a
# commit object embeds its whole patch); bound them separately from MAX_JSON.
API_LISTING_LIMIT = 4 * 1024 * 1024
# Default per-command bound stays 120 s. Only the bounded artifact ZIP and run-log
# downloads (production return ~110 MB) may take longer on a slow/loaded host.
COMMAND_TIMEOUT = 120
DOWNLOAD_TIMEOUT = 1800


def command(argv, *, data=None, limit=protocol.MAX_JSON, timeout=COMMAND_TIMEOUT,
            stderr_limit=protocol.MAX_JSON):
    """Bound both pipes while reading; kill/reap our process group on refusal."""
    require(type(limit) is int and 0 < limit <= 512 * 1024 * 1024
            and type(stderr_limit) is int and 0 < stderr_limit <= protocol.MAX_JSON
            and 0 < timeout <= DOWNLOAD_TIMEOUT and (data is None or
                isinstance(data, bytes) and len(data) <= protocol.MAX_JSON), 'local_command')
    proc, completed = None, False
    selector = selectors.DefaultSelector()
    stdout, stderr_bytes, written = bytearray(), 0, 0
    deadline = time.monotonic() + timeout
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE if data else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, bufsize=0)
        for stream, name in ((proc.stdout, 'stdout'), (proc.stderr, 'stderr')):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        if data:
            os.set_blocking(proc.stdin.fileno(), False)
            selector.register(proc.stdin, selectors.EVENT_WRITE, 'stdin')
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'local_command')
            for key, _ in selector.select(min(0.25, remaining)):
                stream, name = key.fileobj, key.data
                if name == 'stdin':
                    written += os.write(stream.fileno(), data[written:written + 65536])
                    if written == len(data):
                        selector.unregister(stream)
                        stream.close()
                    continue
                cap = limit - len(stdout) if name == 'stdout' else stderr_limit - stderr_bytes
                chunk = os.read(stream.fileno(), min(65536, cap + 1))
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                else:
                    require(len(chunk) <= cap, 'local_command')
                    if name == 'stdout':
                        stdout.extend(chunk)
                    else:
                        stderr_bytes += len(chunk)
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'local_command')
        require(proc.wait(timeout=remaining) == 0, 'local_command')
        completed = True
        return bytes(stdout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BridgeError('local_command') from exc
    finally:
        selector.close()
        if proc is not None:
            if not completed:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=5)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None:
                    stream.close()


def gh(endpoint, *, payload=None, method='GET', raw=False, limit=protocol.MAX_JSON, timeout=COMMAND_TIMEOUT):
    require(endpoint.startswith(('repos/', 'https://uploads.github.com/repos/')), 'api_endpoint')
    args = ['gh', 'api', '--method', method, '-H', 'X-GitHub-Api-Version: 2022-11-28', endpoint]
    if payload is not None:
        args += ['--input', '-']
    result = command(args, data=None if payload is None else json.dumps(payload).encode(), limit=limit,
                     timeout=timeout)
    return result if raw else (json.loads(result) if result else None)


def save(path, receipt):
    protocol.write_json(path, receipt)


def load(path):
    require(not Path(path).is_symlink(), 'receipt_symlink')
    path = Path(path).resolve()
    require(path.name == 'receipt.json', 'receipt_name')
    allowed = (PROJECT / 'software/build/publishing/macos').resolve()
    require(path.is_relative_to(allowed) and not path.is_symlink(), 'receipt_location')
    require(path.stat().st_mode & 0o077 == 0 and path.parent.stat().st_mode & 0o077 == 0,
            'receipt_permissions')
    receipt = protocol.read_json(path)
    mode = receipt.get('mode')
    require(mode in ('fixture', 'production') and receipt.get('schema') == protocol.schema({'mode': mode}, 'host'),
            'receipt_schema')
    cfg = receipt['binding']
    # Validate the exact same parsing invariants without trusting receipt types.
    parsed = protocol.inputs(dict(
        BRIDGE_MODE=mode, BRIDGE_WRAPPER_SHA256=cfg.get('wrapper_sha256'),
        BRIDGE_WORKFLOW_SHA256=cfg.get('workflow_sha256'), GITHUB_REPOSITORY=cfg['repository'],
        GITHUB_WORKFLOW_REF=cfg['workflow_ref'], GITHUB_SHA=cfg['head_sha'],
        GITHUB_RUN_ID=str(cfg.get('run_id', 1)), GITHUB_RUN_ATTEMPT='1',
        GITHUB_EVENT_NAME='workflow_dispatch', BRIDGE_FAIL=str(receipt['fail_fixture']).lower(),
        BRIDGE_NONCE=cfg['nonce'], BRIDGE_SOURCE=cfg['source'],
        BRIDGE_CAPSULE_SHA256=cfg['capsule_sha256'],
        BRIDGE_RETURN_CERT_SHA256=cfg['return_cert_sha256'],
        BRIDGE_DRAFT_ID=str(receipt['draft_id'])))
    require(receipt['tag'] == 'native-bridge-' + parsed['nonce'], 'receipt_tag')
    return path, receipt


def validate_run(run, receipt, workflow):
    b = receipt['binding']
    require(run.get('repository', {}).get('full_name') == b['repository']
            and run.get('head_repository', {}).get('full_name') == b['repository']
            and run.get('event') == 'workflow_dispatch'
            and run.get('actor', {}).get('login') == receipt['actor']
            and run.get('triggering_actor', {}).get('login') == receipt['actor']
            and run.get('head_sha') == b['head_sha']
            and run.get('head_branch') == receipt['ref']
            and run.get('run_attempt') == 1
            and run.get('display_title') == 'native-fixture-' + b['nonce']
            and run.get('workflow_id') == receipt['workflow_id']
            and workflow.get('id') == receipt['workflow_id']
            and workflow.get('path') == receipt['workflow'], 'run_binding')
    run_id = protocol.integer(run.get('id'))
    require('run_id' not in b or b['run_id'] == run_id, 'run_id')
    created = dt.datetime.fromisoformat(run['created_at'].replace('Z', '+00:00')).timestamp()
    require(receipt['created'] - 60 <= created <= receipt['created'] + 600, 'run_time')
    require(b['workflow_ref'] == b['repository'] + '/' + receipt['workflow']
            + '@refs/heads/' + receipt['ref'], 'workflow_ref')
    return run_id


def get_run(receipt, run_id=None):
    repo = receipt['binding']['repository']
    workflow = gh(f"repos/{repo}/actions/workflows/{receipt['workflow_id']}")
    if run_id is None:
        run_id = receipt['binding'].get('run_id')
    if run_id is None:
        listing = gh(f"repos/{repo}/actions/workflows/{receipt['workflow_id']}/runs?event=workflow_dispatch"
                     f"&head_sha={protocol.hexval(receipt['binding']['head_sha'], 40)}&per_page=100",
                     limit=API_LISTING_LIMIT)
        matches = [r for r in listing['workflow_runs']
                   if r.get('display_title') == 'native-fixture-' + receipt['binding']['nonce']]
        require(len(matches) == 1, 'run_lookup_pending_or_ambiguous')
        run_id = protocol.integer(matches[0]['id'])
    run = gh(f'repos/{repo}/actions/runs/{protocol.integer(run_id)}', limit=API_LISTING_LIMIT)
    validate_run(run, receipt, workflow)
    return run


def draft(receipt):
    release = gh(f"repos/{receipt['binding']['repository']}/releases/{receipt['draft_id']}")
    require(release.get('id') == receipt['draft_id'] and release.get('draft') is True
            and release.get('tag_name') == receipt['tag']
            and release.get('name') == receipt['tag']
            and release.get('target_commitish') == receipt['binding']['head_sha'], 'draft_binding')
    return release


def artifact_list(receipt):
    repo, run = receipt['binding']['repository'], receipt['binding']['run_id']
    result = gh(f'repos/{repo}/actions/runs/{run}/artifacts?per_page=100')
    require(type(result.get('total_count')) is int and result['total_count'] < 100
            and len(result['artifacts']) == result['total_count'], 'artifact_inventory')
    return result['artifacts']


def artifact_name(receipt, phase):
    b = receipt['binding']
    return f"native-{phase}-{b['run_id']}-1-{b['nonce']}"


def validate_artifact(item, receipt, phase):
    b = receipt['binding']
    require(item.get('name') == artifact_name(receipt, phase) and item.get('expired') is False
            and type(item.get('size_in_bytes')) is int
            and 0 < item['size_in_bytes'] <= protocol.return_policy(receipt)[0]
            and item.get('workflow_run', {}).get('id') == b['run_id']
            and item.get('workflow_run', {}).get('head_sha') == b['head_sha'], 'artifact_binding')
    protocol.integer(item.get('id'))
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', item.get('digest', '')), 'artifact_digest')


def zip_members(raw, expected=None, *, cap=protocol.MAX_PAYLOAD):
    require(0 < len(raw) <= cap, 'zip_size')
    result, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for member in archive.infolist():
            require(not member.is_dir() and member.filename not in result
                    and '/' not in member.filename and '\\' not in member.filename
                    and member.filename not in ('.', '..')
                    and member.file_size <= cap
                    and member.external_attr >> 16 & 0o170000 not in (0o120000, 0o060000),
                    'zip_inventory')
            total += member.file_size
            require(total <= cap and len(result) < 20, 'zip_size')
            result[member.filename] = archive.read(member)
    if expected is not None:
        require(set(result) == set(expected), 'zip_inventory')
    return result


def get_artifact(receipt, phase, *, listed=None, canary=None):
    listed = artifact_list(receipt) if listed is None else listed
    scan_public_plaintext(listed, canary)
    matches = [a for a in listed if a.get('name') == artifact_name(receipt, phase)]
    require(len(matches) == 1, 'artifact_pending_or_duplicate')
    item = matches[0]
    validate_artifact(item, receipt, phase)
    previous = receipt.get(phase + '_artifact')
    recorded = {k: item[k] for k in ('id', 'digest', 'name')}
    require(previous is None or previous == recorded, 'artifact_changed')
    raw = gh(f"repos/{receipt['binding']['repository']}/actions/artifacts/{item['id']}/zip",
             raw=True, limit=protocol.return_policy(receipt)[0], timeout=DOWNLOAD_TIMEOUT)
    require('sha256:' + protocol.digest(raw) == item['digest'], 'artifact_hash')
    expected = ('recipient.pem', 'identity.json') if phase == 'recipient' else ('encrypted-return.cms', 'identity.json')
    members = zip_members(raw, expected, cap=protocol.return_policy(receipt)[0])
    require(len(members['identity.json']) <= protocol.MAX_JSON, 'identity_size')
    if phase == 'recipient':
        require(len(members['recipient.pem']) <= 65536, 'certificate_size')
    for name, content in members.items():
        if name != 'encrypted-return.cms':
            scan_public_plaintext(content, canary)
    protocol.parse_public_identity(members['identity.json'], receipt['binding'], phase)
    return members, recorded, raw


def _start(args):
    require(args.mode in ('fixture', 'production'), 'mode')
    production = args.mode == 'production'
    if production:
        import native_production
        require(not args.fail_fixture, 'production_fixture_switch')
        require(args.workflow == '.github/workflows/native-capsule.yml', 'production_workflow')
    protocol.hexval(args.head, 40)
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repo), 'repository')
    require(re.fullmatch(r'[A-Za-z0-9_.-]+', args.actor), 'actor')
    require(re.fullmatch(r'[A-Za-z0-9_./-]+', args.ref) and '..' not in args.ref, 'ref')
    require(re.fullmatch(r'\.github/workflows/[A-Za-z0-9_-]+\.yml', args.workflow), 'workflow')
    base = PROJECT / 'software/build/publishing/macos'
    directory = Path(args.directory).resolve()
    require(directory.is_relative_to(base.resolve()) and directory != base.resolve(), 'directory')
    receipt_path = directory / 'receipt.json'
    if receipt_path.exists():
        _, receipt = load(receipt_path)
        require(receipt['binding']['repository'] == args.repo
                and receipt['binding']['head_sha'] == args.head
                and receipt['workflow'] == args.workflow and receipt['ref'] == args.ref
                and receipt['actor'] == args.actor and receipt['fail_fixture'] == args.fail_fixture
                and receipt['mode'] == args.mode
                and (not production or (receipt['binding']['wrapper_sha256'] == args.wrapper_sha256
                    and receipt['binding']['workflow_sha256'] == args.workflow_sha256)),
                'resume_binding')
        if production:
            fixture_gates(args.positive_fixture_receipt, args.negative_fixture_receipt,
                head=args.head, repository=args.repo, actor=args.actor, workflow=args.workflow,
                workflow_id=receipt['workflow_id'], workflow_ref=receipt['binding']['workflow_ref'])
        return {'status': 'resume', 'receipt': str(receipt_path)}
    require(not directory.exists(), 'directory_exists')
    # Branch ref object only; the commit endpoint embeds the full patch.
    head = gh(f'repos/{args.repo}/git/ref/heads/{args.ref}')
    require(head.get('ref') == 'refs/heads/' + args.ref and head.get('object', {}).get('type') == 'commit'
            and head['object'].get('sha') == args.head, 'ref_changed')
    workflow = gh(f'repos/{args.repo}/actions/workflows/{args.workflow.rsplit("/", 1)[-1]}')
    require(workflow.get('path') == args.workflow and workflow.get('state') == 'active', 'workflow')
    protocol.integer(workflow.get('id'))
    if production:
        fixture_gates(args.positive_fixture_receipt, args.negative_fixture_receipt,
            head=args.head, repository=args.repo, actor=args.actor, workflow=args.workflow,
            workflow_id=workflow['id'], workflow_ref=args.repo + '/' + args.workflow + '@refs/heads/' + args.ref)
    directory.mkdir(mode=0o700, parents=True)
    os.chmod(directory, 0o700)
    capsule.PROJECT = PROJECT
    keys = capsule.keygen(directory / 'return-key', openssl=args.openssl)
    if production:
        repo, source = PROJECT, native_production.SOURCE
    else:
        repo = directory / 'fixture-repo'
        repo.mkdir(mode=0o700)
        selected = repo / protocol.FIXTURE
        selected.mkdir(parents=True)
        (repo / '.gitignore').write_bytes(b'build/\n')
        (selected / 'main.c').write_bytes(protocol.MAIN)
        canary = 'PRIVATE-FIXTURE-' + secrets.token_hex(32) + '\n'
        (selected / 'private-canary.txt').write_text(canary)
        (repo / 'hardware').mkdir()
        (repo / 'hardware/excluded.bin').write_bytes(b'NON-SENSITIVE EXCLUDED FIXTURE BLOB\n')
        def git(*argv):
            return capsule._git(repo, *argv)
        git('init', '-q')
        git('add', '.')
        # Real fixture commit; no private product source/worktree is read.
        git('-c', 'user.name=Native Fixture', '-c', 'user.email=fixture@example.invalid',
            'commit', '-qm', 'nonsensitive bridge fixture')
        source = git('rev-parse', 'HEAD').decode().strip()
    prepared = capsule.prepare(repo, source, keys['certificate'], directory / 'capsule.tar', openssl=args.openssl)
    nonce = secrets.token_hex(16)
    binding = dict(repository=args.repo, workflow_ref=args.repo + '/' + args.workflow + '@refs/heads/' + args.ref,
                   head_sha=args.head, attempt=1, nonce=nonce, source=source,
                   capsule_sha256=prepared['capsule_sha256'], return_cert_sha256=keys['certificate_sha256'])
    if production:
        wrapper = native_production.wrapper_identity(Path(__file__).parent)
        require(wrapper['wrapper_sha256'] == args.wrapper_sha256
                and wrapper['workflow_sha256'] == args.workflow_sha256, 'reviewed_wrapper')
        remote_wrapper = {}
        for name in native_production.WRAPPERS:
            value = gh(f'repos/{args.repo}/contents/software/publishing/macos/{name}?ref={args.head}',
                       limit=API_LISTING_LIMIT)
            require(value.get('encoding') == 'base64', 'wrapper_remote')
            remote_wrapper[name] = protocol.digest(base64.b64decode(value['content']))
        workflow_bytes = gh(f'repos/{args.repo}/contents/{args.workflow}?ref={args.head}',
                            limit=API_LISTING_LIMIT)
        require(protocol.digest(json.dumps(remote_wrapper, sort_keys=True).encode()) == wrapper['wrapper_sha256']
                and protocol.digest(base64.b64decode(workflow_bytes['content'])) == wrapper['workflow_sha256'], 'wrapper_remote')
        binding.update(mode='production', **wrapper)
    tag = 'native-bridge-' + nonce
    receipt = dict(schema=protocol.schema({'mode': args.mode}, 'host'), mode=args.mode, binding=binding,
                   workflow=args.workflow, workflow_id=workflow['id'], actor=args.actor,
                   ref=args.ref, tag=tag, created=time_now(), fail_fixture=args.fail_fixture,
                   phase='prepared', openssl=args.openssl, draft_id=0)
    if production:
        receipt['fixture_proofs'] = {name: dict(path=str(Path(path).resolve()), sha256=native_production.sha(path))
            for name, path in (('positive', args.positive_fixture_receipt), ('negative', args.negative_fixture_receipt))}
    save(receipt_path, receipt)
    release = gh(f'repos/{args.repo}/releases', method='POST', payload=dict(
        tag_name=tag, name=tag, target_commitish=args.head, draft=True,
        body='Nonsensitive encrypted native fixture transport.'))
    receipt['draft_id'] = protocol.integer(release.get('id'))
    receipt['phase'] = 'dispatch_attempted'
    # Save before dispatch: a crash/uncertain response never creates another run.
    save(receipt_path, receipt)
    draft(receipt)
    gh(f"repos/{args.repo}/actions/workflows/{workflow['id']}/dispatches", method='POST', payload={
        'ref': args.ref, 'inputs': dict(mode=args.mode, fail_fixture=str(args.fail_fixture).lower(),
          **({k: binding[k] for k in ('wrapper_sha256', 'workflow_sha256')} if production else {}),
          nonce=nonce, draft_release_id=str(receipt['draft_id']), capsule_sha256=binding['capsule_sha256'],
          source_sha=source, return_cert_sha256=binding['return_cert_sha256'])})
    receipt['phase'] = 'dispatched'
    save(receipt_path, receipt)
    return {'status': 'dispatched', 'receipt': str(receipt_path)}


def fixture_gates(positive, negative, *, head, repository, actor, workflow, workflow_id, workflow_ref):
    for path, failed in ((positive, False), (negative, True)):
        _, receipt = load(path)
        require(receipt['mode'] == 'fixture' and receipt['phase'] == 'cleaned'
                and receipt.get('fail_fixture') is failed
                and receipt.get('github_conclusion') == ('failure' if failed else 'success')
                and receipt.get('negative_condition_verified') is failed
                and receipt.get('unexpected_zip_member_rejected') is failed
                and receipt.get('public_privacy_verified') is True
                and receipt['binding']['head_sha'] == head
                and receipt['binding']['repository'] == repository
                and receipt['actor'] == actor
                and receipt.get('workflow') == workflow
                and type(receipt.get('workflow_id')) is int and receipt['workflow_id'] == workflow_id
                and receipt['binding'].get('workflow_ref') == workflow_ref, 'fixture_gate')


def start_fixture(args):
    require(args.mode == 'fixture', 'production_disabled')
    return _start(args)


def start_production(args):
    require(args.mode == 'production', 'mode')
    return _start(args)


def private_canary(receipt, root):
    return ((root / ('fixture-repo/' + protocol.FIXTURE + 'private-canary.txt')).read_bytes().strip()
            if receipt['mode'] == 'fixture' else None)


def time_now():
    return dt.datetime.now(dt.timezone.utc).timestamp()


def feed(path, run_id=None):
    path, receipt = load(path)
    require(receipt['phase'] in ('dispatched', 'dispatch_attempted', 'fed'), 'phase')
    require(time_now() - receipt['created'] < 1200, 'stale')
    if receipt['mode'] == 'production':
        import native_production as production
        proofs = receipt['fixture_proofs']
        require(all(production.sha(p['path']) == p['sha256'] for p in proofs.values()), 'fixture_proof_changed')
        fixture_gates(proofs['positive']['path'], proofs['negative']['path'],
            head=receipt['binding']['head_sha'], repository=receipt['binding']['repository'], actor=receipt['actor'],
            workflow=receipt['workflow'], workflow_id=receipt['workflow_id'], workflow_ref=receipt['binding']['workflow_ref'])
        require(production.wrapper_identity(Path(__file__).parent) ==
            {k: receipt['binding'][k] for k in ('wrapper_sha256', 'workflow_sha256')}, 'wrapper_changed')
    run = get_run(receipt, run_id)
    require(run.get('status') == 'in_progress' and run.get('conclusion') is None, 'run_not_live')
    receipt['binding']['run_id'] = run['id']
    root = path.parent
    canary = private_canary(receipt, root)
    public, artifact, _ = get_artifact(receipt, 'recipient', canary=canary)
    identity = json.loads(public['identity.json'])
    protocol.binding(identity, receipt['binding'])
    require(identity.get('schema') == protocol.schema(receipt, 'recipient')
            and identity.get('recipient_cert_sha256') == protocol.digest(public['recipient.pem'])
            and b'PRIVATE KEY' not in public['recipient.pem'], 'recipient')
    old = receipt.get('recipient_cert_sha256')
    require(old is None or old == identity['recipient_cert_sha256'], 'recipient_changed')
    capsule._cert(public['recipient.pem'], receipt['openssl'])
    receipt['recipient_artifact'] = artifact
    receipt['recipient_cert_sha256'] = identity['recipient_cert_sha256']
    save(path, receipt)
    cert = root / 'runner-recipient.pem'
    cert.write_bytes(public['recipient.pem'])
    cert.chmod(0o600)
    encrypted = root / ('capsule-' + receipt['binding']['nonce'] + '.cms')
    require(protocol.digest((root / 'capsule.tar').read_bytes()) == receipt['binding']['capsule_sha256'],
            'local_capsule_changed')
    if encrypted.exists():
        require(receipt.get('ciphertext_sha256') == protocol.digest(encrypted.read_bytes()), 'ciphertext_changed')
    else:
        sealed = capsule.encrypt(root / 'capsule.tar', cert, encrypted, openssl=receipt['openssl'])
        receipt['ciphertext_sha256'] = sealed['sha256']
        save(path, receipt)
    # Revalidate the exact run immediately before releasing any capsule bytes.
    fresh = get_run(receipt, run['id'])
    require(fresh.get('status') == 'in_progress' and fresh.get('conclusion') is None, 'run_not_live')
    draft(receipt)
    endpoint = f"repos/{receipt['binding']['repository']}/releases/{receipt['draft_id']}/assets?per_page=100"
    assets = gh(endpoint)
    asset = protocol.select_asset(assets, receipt['binding'])
    if asset:
        raw = command(['gh', 'api', '-H', 'Accept: application/octet-stream',
            f"repos/{receipt['binding']['repository']}/releases/assets/{asset['id']}"], limit=protocol.MAX_PAYLOAD)
        require(protocol.digest(raw) == receipt['ciphertext_sha256'], 'existing_asset_changed')
    else:
        url = (f"https://uploads.github.com/repos/{receipt['binding']['repository']}/releases/"
               f"{receipt['draft_id']}/assets?name={encrypted.name}")
        response = command(['gh', 'api', '--method', 'POST', '-H', 'Content-Type: application/octet-stream',
                            url, '--input', str(encrypted)])
        uploaded = json.loads(response)
        require(uploaded.get('name') == encrypted.name and uploaded.get('state') == 'uploaded'
                and uploaded.get('size') == encrypted.stat().st_size, 'upload_result')
        protocol.integer(uploaded.get('id'))
    receipt['phase'] = 'fed'
    save(path, receipt)
    return {'status': 'fed', 'run_id': run['id']}


def unpack_return(raw, config=None):
    """Only flat, bounded evidence/products files; do not use extractall."""
    cap, member_cap, evidence_names, product_names = protocol.return_policy(config or {})
    require(0 < len(raw) <= cap, 'return_size')
    files, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            require(re.fullmatch(r'(evidence|products)/[A-Za-z0-9_.-]+', member.name)
                    and member.isreg() and not member.pax_headers
                    and member.name not in files and 0 <= member.size <= member_cap,
                    'return_inventory')
            folder, name = member.name.split('/')
            require(name in (evidence_names if folder == 'evidence' else product_names),
                    'return_inventory')
            total += member.size
            require(total <= cap and len(files) < 64, 'return_size')
            files[member.name] = archive.extractfile(member).read()
    require('evidence/result.json' in files and ((config or {}).get('mode') == 'production' or 'evidence/private-diagnostic.txt' in files),
            'return_missing')
    require(not any('PRIVATE KEY' in name or '.git' in name for name in files), 'return_inventory')
    return files


def verify_native(files, receipt, run, identity):
    require(len(files['evidence/result.json']) <= protocol.MAX_JSON, 'result_size')
    result = json.loads(files['evidence/result.json'])
    protocol.binding(result, receipt['binding'])
    require(result.get('schema') == 'native-fixture.result.v1' and result.get('protocol') == 'ok', 'native_protocol')
    expected_outputs = {name: dict(sha256=protocol.digest(data), bytes=len(data))
                        for name, data in files.items() if name != 'evidence/result.json'}
    require(result.get('outputs') == expected_outputs, 'output_hashes')
    probes = result.get('probes', {})
    require(set(probes) == set(protocol.PROBE_NAMES)
            and all(type(code) is int and code == 0 for code in probes.values()), 'tool_probes')
    require(all(files.get('evidence/' + name + '.log', b'').strip()
                for name in protocol.PROBE_NAMES), 'tool_probe_logs')
    checks = result.get('native', {})
    expected = set(protocol.NATIVE_STEPS) | ({'deliberate_failure'} if receipt['fail_fixture'] else set())
    require(set(checks) == expected and all(type(v) is int for v in checks.values()), 'native_checks')
    require(all(checks[n] == 0 for n in protocol.NATIVE_STEPS), 'native_failed')
    wanted = 'failure' if receipt['fail_fixture'] else 'success'
    require(run.get('conclusion') == wanted and identity.get('outcome') == wanted
            and result.get('outcome') == wanted
            and result.get('native_failed') is receipt['fail_fixture'], 'terminal_outcome')
    if receipt['fail_fixture']:
        require(checks['deliberate_failure'] != 0, 'negative_not_failed')
    payload = zip_members(files['products/fixture.zip'])
    member_rejected = set(payload) != {'fixture'}
    require(member_rejected == receipt['fail_fixture'], 'payload_content')
    if receipt['fail_fixture']:
        require(set(payload) == {'fixture', 'unexpected-private-member.txt'}, 'negative_payload')
    require(payload.get('fixture'), 'missing_binary')
    canary = (Path(receipt['_root']) / ('fixture-repo/' + protocol.FIXTURE + 'private-canary.txt')).read_bytes().strip()
    require(canary in files['evidence/private-diagnostic.txt'], 'canary_missing')
    if receipt['fail_fixture']:
        require(canary in files['evidence/deliberate_failure.log'], 'canary_missing')
    return canary, member_rejected


def scan_public_plaintext(value, canary=None):
    """One disclosure predicate for public bytes and decoded JSON strings.

    Public certificates are permitted; PEM private keys and fixture source are
    not. Ciphertext must never be passed here as if it were plaintext.
    """
    if isinstance(value, bytes):
        scan_public_plaintext_string(value, canary)
        try:
            decoded = json.loads(value)
        except (ValueError, UnicodeError):
            return
        scan_public_plaintext(decoded, canary)
    elif isinstance(value, str):
        # JSON escapes (including escaped newlines and Unicode) are decoded
        # before comparison, so a serialized source/key field cannot evade it.
        scan_public_plaintext_string(value.encode('utf-8'), canary)
    elif isinstance(value, dict):
        for key, item in value.items():
            scan_public_plaintext(key, canary)
            scan_public_plaintext(item, canary)
    elif isinstance(value, list):
        for item in value:
            scan_public_plaintext(item, canary)


def scan_public_plaintext_string(raw, canary):
    require((not canary or canary not in raw)
            and not re.search(rb'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----', raw)
            and protocol.MAIN not in raw, 'public_disclosure')


def scan_logs(raw, canary):
    require(0 < len(raw) <= protocol.MAX_PAYLOAD, 'logs_size')
    total, count = 0, 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for member in archive.infolist():
            count += 1
            require(count < 2000 and member.file_size <= protocol.MAX_PAYLOAD, 'logs_size')
            total += member.file_size
            require(total <= protocol.MAX_PAYLOAD, 'logs_size')
            # Read every byte; an empty/short preview is not a privacy PASS.
            data = archive.read(member)
            scan_public_plaintext(data, canary)
    require(count > 0, 'logs_empty')


def collect(path):
    path, receipt = load(path)
    if receipt['phase'] == 'cleaned':
        return {'status': 'already_collected', 'run_id': receipt['binding']['run_id'],
                'github_conclusion': receipt['github_conclusion']}
    require(receipt['phase'] in ('fed', 'collected'), 'phase')
    run = get_run(receipt)
    require(run.get('status') == 'completed', 'run_not_terminal')
    wanted = 'failure' if receipt['fail_fixture'] else 'success'
    require(run.get('conclusion') in (('success', 'failure') if receipt['mode'] == 'production' else (wanted,)), 'terminal_outcome')
    wanted = run['conclusion']
    inventory = artifact_list(receipt)
    require({a.get('name') for a in inventory} == {artifact_name(receipt, 'recipient'), artifact_name(receipt, 'return')}
            and len(inventory) == 2, 'public_artifact_inventory')
    root = path.parent
    public_canary = private_canary(receipt, root)
    recipient, recipient_id, _ = get_artifact(receipt, 'recipient', listed=inventory, canary=public_canary)
    require(recipient_id == receipt['recipient_artifact'], 'recipient_artifact_changed')
    public, artifact, _ = get_artifact(receipt, 'return', listed=inventory, canary=public_canary)
    identity = json.loads(public['identity.json'])
    protocol.binding(identity, receipt['binding'])
    require(identity.get('schema') == protocol.schema(receipt, 'return')
            and identity.get('outcome') == wanted, 'return_identity')
    protocol.hexval(identity.get('plaintext_sha256'), 64)
    require(type(identity.get('plaintext_bytes')) is int and 0 < identity['plaintext_bytes'] <= protocol.return_policy(receipt)[0]
            and identity.get('ciphertext_sha256') == protocol.digest(public['encrypted-return.cms'])
            and identity.get('ciphertext_bytes') == len(public['encrypted-return.cms']), 'return_hash')
    # Save trusted-run artifact binding before decrypt; resume cannot switch IDs/digests.
    receipt['return_artifact'] = artifact
    save(path, receipt)
    encrypted = root / 'encrypted-return.cms'
    encrypted.write_bytes(public['encrypted-return.cms'])
    encrypted.chmod(0o600)
    tar = root / 'decrypted-return.tar'
    if tar.exists():
        require(protocol.digest(tar.read_bytes()) == identity['plaintext_sha256'], 'return_changed')
    else:
        capsule.decrypt(encrypted, root / 'return-key/recipient.pem', root / 'return-key/recipient.key',
                        tar, identity['plaintext_sha256'], openssl=receipt['openssl'])
    require(tar.stat().st_size == identity['plaintext_bytes'], 'return_size')
    files = unpack_return(tar.read_bytes(), receipt)
    receipt['_root'] = str(root)
    if receipt['mode'] == 'production':
        import native_production
        native_production.bound_result(files, receipt)
        if wanted == 'success':
            native_production.verify_return(files, receipt, run, identity)
        canary, rejected = None, False
    else:
        canary, rejected = verify_native(files, receipt, run, identity)
    del receipt['_root']
    logs = gh(f"repos/{receipt['binding']['repository']}/actions/runs/{run['id']}/logs",
              raw=True, limit=protocol.MAX_PAYLOAD, timeout=DOWNLOAD_TIMEOUT)
    scan_logs(logs, canary)
    out = root / 'reviewed-return'
    out.mkdir(mode=0o700, exist_ok=True)
    for name, data in files.items():
        target = out / name
        target.parent.mkdir(mode=0o700, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o600)
    if receipt['mode'] == 'production':
        if wanted == 'success':
            prepare_content_review(root, receipt, out)
        else:
            receipt.update(content_review='native-failure', production_accepted=False)
    receipt.update(phase='collected', github_conclusion=run['conclusion'],
                   negative_condition_verified=receipt['fail_fixture'],
                   unexpected_zip_member_rejected=rejected, public_privacy_verified=True,
                   return_plaintext_sha256=identity['plaintext_sha256'],
                   return_result_sha256=protocol.digest(files['evidence/result.json']))
    save(path, receipt)
    # Cleanup is restricted to the numeric draft recorded for this transaction.
    draft(receipt)
    gh(f"repos/{receipt['binding']['repository']}/releases/{receipt['draft_id']}", method='DELETE')
    receipt['phase'] = 'cleaned'
    save(path, receipt)
    return {'status': ('failure-evidence-collected' if receipt['mode'] == 'production' and wanted == 'failure' else 'collected'), 'run_id': run['id'], 'github_conclusion': run['conclusion'],
            'negative_condition_verified': receipt['fail_fixture'], 'public_privacy_verified': True}


def prepare_content_review(root, receipt, out):
    """Independent source-941 verifier and full inventory; no public upload."""
    import native_production as production
    source = root / 'source-review'
    if not source.exists():
        capsule.verify_extract(root / 'capsule.tar', receipt['binding']['capsule_sha256'],
            production.SOURCE, source, openssl=receipt['openssl'])
    expected_source = production.source_receipt(source)
    returned_source = json.loads((out / 'evidence/source-receipt.json').read_bytes())
    require({k: returned_source.get(k) for k in expected_source} == expected_source, 'source_receipt')
    artifact = out / 'products' / production.ZIP_NAME
    # Enforce complete decompression bounds before either independent ZIP consumer.
    entries = production.payload_inventory(artifact)
    argv = ['python3', str(source / 'software/publishing/macos/release.py'), 'verify',
        '--artifact', str(artifact), '--manifest', str(out / 'products/manifest.json'),
        '--pubspec', str(source / 'software/apps/carbonic/pubspec.yaml'), '--source', production.SOURCE]
    with (root / 'independent-release-verify.log').open('wb') as stream:
        require(subprocess.run(argv, env=protocol.build_env(root), stdout=stream,
            stderr=subprocess.STDOUT, timeout=120).returncode == 0, 'independent_release_verify')
    cask = root / 'independent-carbonic.rb'
    with (root / 'independent-cask.log').open('wb') as stream:
        require(subprocess.run([*argv[:2], 'cask', *argv[3:], '--output', str(cask)],
            env=protocol.build_env(root), stdout=stream, stderr=subprocess.STDOUT,
            timeout=120).returncode == 0, 'independent_cask')
    require(cask.read_bytes() == (out / 'products/carbonic.rb').read_bytes(), 'independent_cask')
    baseline_path = PROJECT / 'software/build/publishing/macos/accepted-0.1.1-bundle-inventory.json'
    baseline_raw = baseline_path.read_bytes()
    require(protocol.digest(baseline_raw) == '18aae28bac788d8624828282fab372d88750e2b31997033192469aa516dc91f8', 'baseline_inventory')
    baseline = json.loads(baseline_raw)
    old = {e['path']: e for e in baseline['entries']}
    current = {e['name']: e for e in entries}
    inventory = dict(schema='native-production.content-inventory.v1', source=production.SOURCE,
        binding=receipt['binding'], zip_sha256=production.sha(artifact),
        baseline_sha256=protocol.digest(baseline_raw), entries=entries,
        additions=sorted(set(current) - set(old)), removals=sorted(set(old) - set(current)),
        changed=sorted(n for n in current.keys() & old.keys()
            if current[n]['sha256'] != old[n]['sha256'] or current[n]['mode'] != int(old[n]['mode'], 8)))
    # Larger than protocol metadata: the complete inventory is private review evidence.
    target = root / 'content-inventory.json'
    target.write_text(json.dumps(inventory, sort_keys=True, indent=2) + '\n')
    target.chmod(0o600)
    receipt.update(content_inventory_sha256=production.sha(target), content_review='pending',
                   independent_release_verify=True)


def accept_production(path, review):
    import native_production as production
    path, receipt = load(path)
    require(receipt['mode'] == 'production' and receipt['phase'] == 'cleaned'
            and receipt.get('github_conclusion') == 'success'
            and receipt.get('public_privacy_verified') is True
            and receipt.get('independent_release_verify') is True, 'production_not_collected')
    inventory_path = path.parent / 'content-inventory.json'
    inventory = json.loads(inventory_path.read_bytes())
    approval = protocol.read_json(review)
    require(approval.get('schema') == 'native-production.content-review.v1'
        and approval.get('inventory_sha256') == receipt.get('content_inventory_sha256') == production.sha(inventory_path)
        and approval.get('zip_sha256') == inventory['zip_sha256']
        and approval.get('source') == production.SOURCE
        and approval.get('all_members_reviewed') is True
        and approval.get('native_screenshots_and_logs_reviewed') is True
        and approval.get('verdict') == 'approved', 'content_review')
    protocol.binding(approval.get('binding', {}), receipt['binding'])
    explanations = approval.get('addition_explanations', {})
    require(set(explanations) == set(inventory['additions']) and all(isinstance(v, str) and v.strip()
        for v in explanations.values()), 'unreviewed_additions')
    # Recheck every returned byte and native gate after review, not only the app ZIP.
    out = path.parent / 'reviewed-return'
    files = {str(p.relative_to(out)): p.read_bytes() for p in out.rglob('*') if p.is_file()}
    require(protocol.digest(files.get('evidence/result.json', b'')) == receipt.get('return_result_sha256'), 'result_changed')
    production.verify_return(files, receipt, {'conclusion': 'success'}, {'outcome': 'success'})
    require(production.payload_inventory(out / 'products' / production.ZIP_NAME) == inventory['entries'], 'inventory_changed')
    receipt.update(content_review='approved', content_review_sha256=production.sha(review),
                   production_accepted=True, published=False)
    save(path, receipt)
    return dict(status='accepted-for-owner-publication', published=False,
                inventory_sha256=receipt['content_inventory_sha256'])


def cleanup_fixture(path, run_id=None):
    """Terminal failure/cancellation cleanup; never claims evidence acceptance."""
    path, receipt = load(path)
    if receipt['phase'] in ('cleaned', 'transport_removed'):
        return {'status': 'transport_already_removed'}
    run = get_run(receipt, run_id)
    require(run.get('status') == 'completed', 'run_not_terminal')
    receipt['binding']['run_id'] = run['id']
    draft(receipt)
    gh(f"repos/{receipt['binding']['repository']}/releases/{receipt['draft_id']}", method='DELETE')
    receipt.update(phase='transport_removed', github_conclusion=run.get('conclusion'))
    save(path, receipt)
    return {'status': 'transport_removed', 'github_conclusion': run.get('conclusion')}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for name, mode in (('start-fixture', 'fixture'), ('start-production', 'production')):
        start = sub.add_parser(name)
        start.add_argument('--mode', default=mode)
        for flag in ('repo', 'ref', 'head', 'workflow', 'actor', 'directory'):
            start.add_argument('--' + flag, required=True)
        start.add_argument('--openssl', default='openssl')
        start.add_argument('--fail-fixture', action='store_true')
        if mode == 'production':
            for flag in ('positive-fixture-receipt', 'negative-fixture-receipt', 'wrapper-sha256', 'workflow-sha256'):
                start.add_argument('--' + flag, required=True)
    review = sub.add_parser('accept-production')
    review.add_argument('--receipt', required=True)
    review.add_argument('--review', required=True)
    for phase in ('feed', 'collect', 'cleanup-fixture'):
        p = sub.add_parser(phase)
        p.add_argument('--receipt', required=True)
        if phase in ('feed', 'cleanup-fixture'):
            p.add_argument('--run-id', type=int)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.command == 'start-fixture':
            result = start_fixture(args)
        elif args.command == 'start-production':
            result = start_production(args)
        elif args.command == 'accept-production':
            result = accept_production(args.receipt, args.review)
        elif args.command == 'feed':
            result = feed(args.receipt, args.run_id)
        elif args.command == 'cleanup-fixture':
            result = cleanup_fixture(args.receipt, args.run_id)
        else:
            result = collect(args.receipt)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print('{"status":"refused","code":"FIXTURE_BRIDGE_REFUSED"}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
