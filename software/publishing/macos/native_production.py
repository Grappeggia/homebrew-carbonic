"""Fixed exact-941 native stages and private return/content gates for the bridge.

No action occurs on import. This module is public wrapper code, never an overlay
on product source. Production bounds are provisional until real native sizing.
"""
from __future__ import annotations
import hashlib
import io
import json
import math
import os
from pathlib import Path
import posixpath
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import time
import zipfile

import capsule
import native_bridge_runner as bridge

SOURCE = '941e32d72ccd1eed60884b1c2de34cbb0fc93ad3'
FLUTTER = 'c197ca5199e9ee5661e865596c9c07294dfab51c'
MAX_RETURN = 512 * 1024 * 1024
MAX_MEMBER = 256 * 1024 * 1024
MAX_ENTRIES = 100000
ZIP_NAME = 'Carbonic-0.1.2-3-macos-universal2.zip'
WRAPPERS = ('capsule.py', 'native_bridge.py', 'native_bridge_runner.py', 'native_production.py')
STEPS = ('source_initial', 'arch_arm64', 'arch_x86_64', 'sdk', 'release', 'freeze',
         'homebrew', 'release_evidence', *tuple(n + '_' + a for a in ('arm64', 'x86_64')
          for n in ('reconstruct', 'debug_build', 'xctest', 'xctest_results', 'debug_arch',
                    'debug_launch', 'debug_package', 'debug_evidence', 'debug_parity')),
         'source_final', 'release_frozen')
NATIVE_TESTS = ('testMaintenanceMustBeExplicitlyFalse', 'testWireFamilyAndEncryptionAreRequired',
    'testNativeRecorderAndCrashSnapshot', 'testUnknownFamilyAndExistingFileAreRefused',
    'testAdvertisedIntegerSamplingRequestPolicy', 'testStatusOnlyIdentityThenFirstNewPacketRejectsDelayedStatus',
    'testDelayedUsbStopsWithoutReplacingNewStreamRate', 'testPausedStatusChangesAndSameSessionMismatch',
    'testNewStatusRetiresOldStreamAndBooleanDescriptorRatesAreRejected',
    'testPreviewFractionalStatusWithoutR4bSessionReachesManualAdmissionAndUsbStop',
    'testFamilyDispatchPreservesR4bIntegerOrderingAndUsbAuthority',
    'testInvalidOrUnreadyRateRequestNeverSubmitsOrInvokesPauseCleanup',
    'testAdmittedSubmissionFailurePurgesRateAndRoutesOwnerPauseCleanup',
    'testAcceptedSubmissionKeepsPendingUntilAsyncConfirmation')
PRODUCTS = {ZIP_NAME, 'manifest.json', 'carbonic.rb', 'README.md'}
EVIDENCE = ({n + '.log' for n in STEPS} | {'source-receipt.json', 'release-frozen.json',
    'release-evidence.tar.gz', 'archive-sizes.json', 'result.json', 'openssl.log'} | {n + '-' + a + ext
    for a in ('arm64', 'x86_64') for n, ext in (
        ('xcresult', '.tar.gz'), ('xctest-results', '.json'), ('xctest-tests', '.json'), ('runtime', '.png'),
        ('development', '.zip'))})
require = bridge.require

RELEASE_MEMBERS = {'flutter-bootstrap.txt', 'flutter-version.json', 'xcode-version.txt', 'macos-version.txt',
    'build.log', 'source-parity.diff', 'codesign-verify.txt', 'codesign-details.txt', 'lipo.json',
    'gatekeeper.txt', 'gatekeeper-exit.txt', 'runtime-pids.txt', 'runtime-process.txt',
    'runtime.png', 'native-checks.json', 'homebrew-checks.json', 'signing-audit-scope.txt', 'upgrade-scope.txt'}
COMMAND_STEPS = {'arch_arm64', 'arch_x86_64', 'sdk', 'release', 'homebrew'} | {
    n + '_' + a for a in ('arm64', 'x86_64') for n in
    ('debug_build', 'xctest', 'xctest_results', 'debug_arch', 'debug_launch', 'debug_package')}
BREW_LABELS = ('version', 'audit-help', 'initial-taps', 'tap-init', 'tap-add', 'tap-commit',
    'tap', 'tap-path', 'style', 'cask-trust', 'trust-receipt', 'audit-public-cask', 'install',
    'installed-integrity', 'installed-quarantine', 'installed-gatekeeper', 'upgrade-current', 'uninstall')


def homebrew_commands(local):
    """Exact command sequence in immutable source-941 verify_homebrew.py."""
    local = str(local)
    token = 'grappeggia/carbonic-prototype-ci/carbonic'
    tap = 'grappeggia/carbonic-prototype-ci'
    appdir = str(Path(local).parent / 'installed-apps')
    app = appdir + '/Carbonic.app'
    return [['brew', '--version'], ['brew', 'audit', '--help'], ['brew', 'tap'],
        ['git', 'init', local], ['git', '-C', local, 'add', 'Casks/carbonic.rb'],
        ['git', '-C', local, '-c', 'user.name=Carbonic CI', '-c', 'user.email=ci@example.invalid',
         'commit', '-m', 'Verify prototype payload'],
        ['brew', 'tap', '--custom-remote', tap, local], ['brew', '--repository', tap],
        ['brew', 'style', '--cask', token], ['brew', 'trust', '--cask', token],
        ['brew', 'trust', '--json=v1'], ['brew', 'audit', '--cask', token],
        ['brew', 'install', '--cask', '--appdir=' + appdir, token],
        ['codesign', '--verify', '--deep', '--strict', app],
        ['xattr', '-p', 'com.apple.quarantine', app],
        ['spctl', '--assess', '--type', 'execute', '--verbose=4', app],
        ['brew', 'upgrade', '--cask', '--appdir=' + appdir, token],
        ['brew', 'uninstall', '--cask', token]]


def release_evidence(members, manifest):
    """Require original builder evidence and match its meaning to frozen products."""
    require(set(members) == RELEASE_MEMBERS | {'brew-' + n + '.log' for n in BREW_LABELS},
            'release_evidence_inventory')
    checks = json.loads(members['native-checks.json'])
    expected = dict(codesign_integrity='passed', standalone_runtime='passed', lipo_universal2='passed',
        gatekeeper='rejected-as-expected', screenshot_sha256=bridge.digest(members['runtime.png']))
    require(checks == expected and manifest.get('native_checks') == checks
            and members['runtime.png'].startswith(b'\x89PNG\r\n\x1a\n'), 'release_native_checks')
    require(json.loads(members['flutter-version.json']).get('frameworkRevision') == FLUTTER,
            'release_sdk')
    require(not members['source-parity.diff'].strip() and b'Signature=adhoc' in members['codesign-details.txt']
            and b'rejected' in members['gatekeeper.txt'].lower()
            and re.fullmatch(rb'[1-9][0-9]*\s*', members['gatekeeper-exit.txt'])
            and re.fullmatch(rb'(?:[1-9][0-9]*\s*)+', members['runtime-pids.txt'])
            and members['runtime-process.txt'].strip(), 'release_native_checks')
    lipo = json.loads(members['lipo.json'])
    require(type(lipo) is dict and len(lipo) >= 4 and all(v == ['arm64', 'x86_64'] for v in lipo.values())
            and {'Carbonic.app/' + k: v for k, v in lipo.items()} == manifest.get('mach_o'), 'release_lipo')
    records = json.loads(members['homebrew-checks.json'])
    require(type(records) is list and len(records) == len(BREW_LABELS), 'homebrew_checks')
    require(all(type(r) is dict for r in records), 'homebrew_checks')
    init = records[3].get('command', [])
    require(type(init) is list and len(init) == 3 and type(init[2]) is str
            and init[2].startswith('/') and '..' not in Path(init[2]).parts
            and init[2].endswith('/software/build/publishing/macos/release/brew-tap-source'), 'homebrew_checks')
    commands = homebrew_commands(init[2])
    for label, record, command in zip(BREW_LABELS, records, commands):
        reject = label == 'installed-gatekeeper'
        require(set(record) == {'command', 'exit_code', 'expected_exit'}
                and record['command'] == command and type(record['exit_code']) is int, 'homebrew_checks')
        if reject:
            require(record['expected_exit'] == 'gatekeeper-rejection' and record['exit_code'] != 0,
                    'homebrew_checks')
        else:
            require(type(record['expected_exit']) is int
                    and record['expected_exit'] == record['exit_code'] == 0, 'homebrew_checks')
    rejection = members['brew-installed-gatekeeper.log'].decode('utf-8')
    require(not re.search(r'invalid option|unknown option|unrecognized|does not exist|unavailable', rejection, re.I)
            and re.search(r'signature verification failed|not notarized|notarization|failed.{0,40}Gatekeeper|code signature|not signed|rejected', rejection, re.I), 'homebrew_gatekeeper')
    require(members['brew-installed-quarantine.log'].strip(), 'homebrew_quarantine')
    trust = json.loads(members['brew-trust-receipt.log'])
    require(trust == dict(taps=[], formulae=[], casks=[(init[2] + '/carbonic').lower()], commands=[]),
            'homebrew_trust')
    require(b'already current' in members['upgrade-scope.txt']
            and b'Cross-version migration' in members['upgrade-scope.txt']
            and b'Ordinary custom-tap audit' in members['signing-audit-scope.txt'], 'homebrew_scope')



def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def wrapper_identity(directory, workflow=None):
    directory = Path(directory)
    hashes = {name: sha(directory / name) for name in WRAPPERS}
    workflow = Path(workflow) if workflow else directory / 'native-capsule.yml'
    return dict(wrapper_sha256=bridge.digest(json.dumps(hashes, sort_keys=True).encode()),
                workflow_sha256=sha(workflow))


def source_receipt(source):
    """The capsule verifier supplies full object/file coverage; retain its gates."""
    require(capsule._git(source, 'rev-parse', 'HEAD').decode().strip() == SOURCE, 'production_source')
    scopes = (*capsule.PARITY_SCOPES, '.github/workflows/carbonic.yml')
    require(not capsule._git(source, 'status', '--porcelain', '--untracked-files=no', '--', *scopes),
            'source_mutation')
    capsule._git(source, 'diff', '--exit-code', SOURCE, '--', *scopes)
    paths = ('software/publishing/macos/build_release.sh', 'software/publishing/macos/release.py',
             'software/publishing/macos/verify_homebrew.py', '.github/workflows/carbonic.yml',
             '.github/workflows/carbonic-release.yml', 'software/apps/carbonic/pubspec.yaml')
    require('version: 0.1.2+3' in (source / paths[-1]).read_text(), 'production_version')
    return dict(source=SOURCE, parity='passed', files={p: sha(source / p) for p in paths},
                capsule_manifest_sha256=sha(source / '.carbonic/manifest.json'))


def pack_directory(directory, output, *, names=None):
    """A named evidence directory, never the workspace; measure complete input."""
    directory, output = Path(directory), Path(output)
    paths = sorted(directory.rglob('*')) if names is None else [directory / n for n in sorted(names)]
    records, total = [], 0
    for path in paths:
        require(not path.is_symlink(), 'evidence_link')
        if path.is_dir():
            continue
        require(path.is_file(), 'evidence_type')
        size = path.stat().st_size
        total += size
        require(size <= MAX_MEMBER and total <= MAX_RETURN and len(records) < MAX_ENTRIES,
                'evidence_size')
        records.append(dict(path=str(path.relative_to(directory)), bytes=size, sha256=sha(path)))
    require(records, 'evidence_empty')
    with tarfile.open(output, 'x:gz', format=tarfile.USTAR_FORMAT) as archive:
        for record in records:
            archive.add(directory / record['path'], arcname=record['path'], recursive=False)
    require(output.stat().st_size <= MAX_MEMBER, 'evidence_size')
    return dict(entries=len(records), uncompressed_bytes=total, archive_bytes=output.stat().st_size,
                sha256=sha(output))


def xctest_summary(data):
    """Require executed passing tests, including the 941 authority regressions."""
    value = json.loads(data)
    require(value.get('result') == 'Passed' and type(value.get('passedTests')) is int
            and value['passedTests'] > 0 and type(value.get('failedTests')) is int
            and value['failedTests'] == 0, 'xctest_results')
    return value


def xctest_cases(data, *, expected=NATIVE_TESTS, target='RunnerTests', klass='RunnerTests'):
    """Parse Xcode16 test-results/tests, observed in generic native probe42514553188.

    The --help JSON Schema defines nodeType/result; the recorded probe proves
    Passed, Skipped and Failed leaves. Only the fixed single-configuration tree
    used by this bridge is accepted. Unknown/ambiguous structures fail closed.
    """
    value = json.loads(data)
    require(type(value) is dict and type(value.get('testNodes')) is list
            and len(value['testNodes']) == 1, 'xctest_coverage')
    def node(value, kind, name=None):
        require(type(value) is dict and value.get('nodeType') == kind
                and type(value.get('name')) is str and value['name']
                and (name is None or value['name'] == name)
                and value.get('result') == 'Passed', 'xctest_coverage')
        return value
    def single(parent, kind, name):
        require(type(parent.get('children')) is list and len(parent['children']) == 1,
                'xctest_coverage')
        return node(parent['children'][0], kind, name)
    plan = node(value['testNodes'][0], 'Test Plan')
    bundle = single(plan, 'Unit test bundle', target)
    suite = single(bundle, 'Test Suite', klass)
    cases = suite.get('children')
    require(type(cases) is list and len(cases) == len(expected)
            and len(set(expected)) == len(expected) and expected, 'xctest_coverage')
    seen, url_project = set(), None
    def url(item, suffix):
        nonlocal url_project
        if 'nodeIdentifierURL' not in item:
            return
        value = item['nodeIdentifierURL']
        prefix = 'test://com.apple.xcode/'
        require(type(value) is str and value.startswith(prefix), 'xctest_coverage')
        parts = value[len(prefix):].split('/')
        require(len(parts) == len(suffix) + 1 and parts[0] and parts[1:] == suffix
                and (url_project is None or parts[0] == url_project), 'xctest_coverage')
        url_project = parts[0]
    url(bundle, [target])
    url(suite, [target, klass])
    for case in cases:
        node(case, 'Test Case')
        name = case['name']
        require(name.endswith('()') and name[:-2] in expected and name not in seen
                and case.get('nodeIdentifier') == klass + '/' + name
                and not case.get('children')
                and type(case.get('durationInSeconds')) in (int, float)
                and math.isfinite(case['durationInSeconds']) and case['durationInSeconds'] >= 0,
                'xctest_coverage')
        url(case, [target, klass, name[:-2]])
        seen.add(name)
    require(seen == {n + '()' for n in expected}, 'xctest_coverage')
    return seen


def owned_pids(executable, env):
    proc = subprocess.run(['ps', '-axo', 'pid=,comm='], env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=10, check=True, text=True)
    return [int(parts[0]) for line in proc.stdout.splitlines()
            if len(parts := line.strip().split(None, 1)) == 2 and parts[1] == str(executable)]


def stop_owned(executable, env):
    for sig, wait in ((signal.SIGTERM, 5), (signal.SIGKILL, 3)):
        for pid in owned_pids(executable, env):
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
        end = time.monotonic() + wait
        while owned_pids(executable, env) and time.monotonic() < end:
            time.sleep(0.2)
    require(not owned_pids(executable, env), 'owned_cleanup')


def launch(executable, screenshot, env, log):
    stop_owned(executable, env)  # retire only our exact XCTest host
    proc = None
    try:
        proc = subprocess.Popen([str(executable)], env=env, stdout=log, stderr=subprocess.STDOUT)
        time.sleep(20)
        require(proc.poll() is None and proc.pid in owned_pids(executable, env), 'debug_runtime')
        subprocess.run(['screencapture', '-x', str(screenshot)], env=env, check=True, timeout=30,
                       stdout=log, stderr=subprocess.STDOUT)
        require(screenshot.stat().st_size > 0, 'debug_screenshot')
        log.write(('owned standalone PID ' + str(proc.pid) + ' executable ' + str(executable) + '\n').encode())
    finally:
        stop_owned(executable, env)
        if proc is not None:
            proc.wait(timeout=5)


def native(root, source, config):
    """Fixed stages; a failed dependency leaves explicit nonzero terminal stages."""
    root, source = Path(root), Path(source)
    products, evidence = root / 'products', root / 'evidence'
    products.mkdir(mode=0o700)
    results = dict.fromkeys(STEPS, 125)
    measurements = {}
    def stage(name, operation):
        try:
            code = operation()
            results[name] = 0 if code is None else code
        except Exception as exc:
            # Diagnostic is private, and contains no traceback or credentials.
            log = evidence / (name + '.log')
            with log.open('ab') as stream:
                stream.write(('private stage exception: ' + type(exc).__name__ +
                    (': ' + str(exc) if isinstance(exc, bridge.BridgeError) and str(exc) in
                     ('arch_execution', 'debug_arch') else '') + '\n').encode())
            results[name] = 125
        require(results[name] == 0, 'native_stage')
    def run(name, argv, cwd=source, timeout=600):
        return lambda: bridge.capture(argv, root, name, cwd=cwd, timeout=timeout, process_group=True)
    def architecture(name, argv, arch, cwd=source):
        code = run(name, argv, cwd=cwd)()
        if code != 0:
            return code
        require((evidence / (name + '.log')).read_text().strip() == arch,
                'debug_arch' if name.startswith('debug_') else 'arch_execution')
    sdk = root / 'sdk/flutter'
    sdk.parent.mkdir(mode=0o700)
    release = source / 'software/build/publishing/macos/release'
    frozen = {}
    def freeze():
        for name, path in {ZIP_NAME: release / ZIP_NAME, 'manifest.json': release / 'manifest.json',
                           'carbonic.rb': release / 'tap/Casks/carbonic.rb',
                           'README.md': source / 'software/publishing/macos/TAP-README.md'}.items():
            require(path.is_file() and not path.is_symlink(), 'release_product')
            shutil.copyfile(path, products / name)
            frozen[name] = dict(sha256=sha(products / name), bytes=(products / name).stat().st_size)
        bridge.write_json(evidence / 'release-frozen.json', frozen)
    def initial():
        receipt = source_receipt(source)
        receipt.update(binding={k: config[k] for k in bridge.identity_fields(config)})
        bridge.write_json(evidence / 'source-receipt.json', receipt)
        require(not (source / 'software/apps/carbonic/build').exists(), 'release_not_fresh')
    def sdk_install():
        commands = [(['git', 'init', str(sdk)], 60),
                    (['git', '-C', str(sdk), 'fetch', '--depth=1', 'https://github.com/flutter/flutter.git', FLUTTER], 600),
                    (['git', '-C', str(sdk), 'fetch', '--depth=1', 'https://github.com/flutter/flutter.git', 'tag', '3.47.9'], 600),
                    (['git', '-C', str(sdk), 'checkout', '--detach', FLUTTER], 60)]
        log = evidence / 'sdk.log'
        with log.open('xb') as stream:
            for argv, timeout in commands:
                require(bridge.private_process(argv, root, stream, timeout=timeout) == 0, 'sdk_install')
            version_path = root / 'sdk-version.json'
            with version_path.open('xb') as version:
                code = bridge.private_process([str(sdk / 'bin/flutter'), '--version', '--machine'],
                    root, version, stderr=stream, timeout=1200)
            data = version_path.read_bytes()
            stream.write(data)
            require(code == 0 and json.loads(data)['frameworkRevision'] == FLUTTER, 'sdk_revision')
    try:
        stage('source_initial', initial)
        for arch in ('arm64', 'x86_64'):
            stage('arch_' + arch, lambda: architecture('arch_' + arch,
                ['/usr/bin/arch', '-' + arch, '/usr/bin/uname', '-m'], arch))
        stage('sdk', sdk_install)
        stage('release', run('release', ['bash', 'software/publishing/macos/build_release.sh'], timeout=2400))
        stage('freeze', freeze)
        stage('homebrew', run('homebrew', ['python3', 'software/publishing/macos/verify_homebrew.py',
                                         '--release-dir', str(release)], timeout=2400))
        def release_evidence():
            # Explicit known original-builder/Homebrew evidence; no tap .git or installed app.
            names = set(RELEASE_MEMBERS)
            names |= {p.name for p in release.glob('brew-*.log')}
            measurements['release-evidence'] = pack_directory(release, evidence / 'release-evidence.tar.gz', names=names)
        stage('release_evidence', release_evidence)
        reconstruction = root / 'reconstruct.tar'
        prepared = capsule.prepare(source, SOURCE, source / '.carbonic/return.pem', reconstruction,
                                   openssl=config['openssl'])
        for arch in ('arm64', 'x86_64'):
            fresh = root / ('debug-' + arch)
            stage('reconstruct_' + arch, lambda: (capsule.verify_extract(reconstruction,
                prepared['capsule_sha256'], SOURCE, fresh, openssl=config['openssl']), source_receipt(fresh), None)[-1])
            app_root = fresh / 'software/apps/carbonic'
            bundle = app_root / 'build/macos/Build/Products/Debug/Carbonic.app'
            executable = bundle / 'Contents/MacOS/Carbonic'
            xcresult = root / ('runtime-' + arch + '.xcresult')
            # Preserve locked resolution/analyze/widget gates on each fresh branch.
            stage('debug_build_' + arch, run('debug_build_' + arch,
                ['bash', '-euc', 'flutter pub get --enforce-lockfile; flutter analyze; flutter test; flutter build macos --debug'],
                cwd=app_root, timeout=1800))
            stage('xctest_' + arch, run('xctest_' + arch, ['xcodebuild', 'test', '-workspace',
                'macos/Runner.xcworkspace', '-scheme', 'Runner', '-configuration', 'Debug', '-destination',
                'platform=macOS,arch=' + arch, '-derivedDataPath', str(app_root / 'build/macos'),
                'ARCHS=' + arch, 'ONLY_ACTIVE_ARCH=YES', '-resultBundlePath', str(xcresult), 'CODE_SIGN_IDENTITY=-'],
                cwd=app_root, timeout=1800))
            def summary():
                output = evidence / ('xctest-results-' + arch + '.json')
                with output.open('xb') as stream, (evidence / ('xctest_results_' + arch + '.log')).open('xb') as diagnostic:
                    code = bridge.private_process(['xcrun', 'xcresulttool', 'get', 'test-results', 'summary',
                        '--path', str(xcresult)], root, stream, stderr=diagnostic, timeout=60)
                require(code == 0, 'xctest_results')
                summary_value = xctest_summary(output.read_bytes())
                tests = evidence / ('xctest-tests-' + arch + '.json')
                with tests.open('xb') as stream, (evidence / ('xctest_results_' + arch + '.log')).open('ab') as diagnostic:
                    code = bridge.private_process(['xcrun', 'xcresulttool', 'get', 'test-results', 'tests',
                        '--path', str(xcresult)], root, stream, stderr=diagnostic, timeout=60)
                require(code == 0, 'xctest_results')
                expected = re.findall(r'func (test[A-Za-z0-9_]+)\(',
                    (fresh / 'software/apps/carbonic/macos/RunnerTests/RunnerTests.swift').read_text())
                require(tuple(expected) == NATIVE_TESTS and summary_value['passedTests'] >= len(expected),
                        'xctest_coverage')
                xctest_cases(tests.read_bytes())
            stage('xctest_results_' + arch, summary)
            stage('debug_arch_' + arch, lambda: architecture('debug_arch_' + arch,
                ['lipo', '-archs', str(executable)], arch, cwd=app_root))
            def debug_launch():
                with (evidence / ('debug_launch_' + arch + '.log')).open('xb') as stream:
                    launch(executable, evidence / ('runtime-' + arch + '.png'), bridge.build_env(root), stream)
            stage('debug_launch_' + arch, debug_launch)
            stage('debug_package_' + arch, run('debug_package_' + arch, ['ditto', '-c', '-k', '--sequesterRsrc',
                '--keepParent', str(bundle), str(evidence / ('development-' + arch + '.zip'))], cwd=app_root))
            def debug_evidence():
                measurements[arch] = pack_directory(xcresult, evidence / ('xcresult-' + arch + '.tar.gz'))
            stage('debug_evidence_' + arch, debug_evidence)
            stage('debug_parity_' + arch, lambda: (source_receipt(fresh), None)[-1])
        stage('source_final', lambda: (source_receipt(source), None)[-1])
        def frozen_check():
            require(frozen == {n: dict(sha256=sha(products / n), bytes=(products / n).stat().st_size)
                               for n in PRODUCTS}, 'release_changed')
            require(all(sha(release / (('tap/Casks/' + n) if n == 'carbonic.rb' else n)) == frozen[n]['sha256']
                        for n in (ZIP_NAME, 'manifest.json', 'carbonic.rb')), 'release_changed')
        stage('release_frozen', frozen_check)
    except Exception:
        pass  # Failed stage remains nonzero; sealing must never turn it into success.
    finally:
        for arch in ('arm64', 'x86_64'):
            executable = root / ('debug-' + arch) / 'software/apps/carbonic/build/macos/Build/Products/Debug/Carbonic.app/Contents/MacOS/Carbonic'
            if executable.is_file():
                try:
                    stop_owned(executable, bridge.build_env(root))
                except Exception as exc:
                    results['debug_launch_' + arch] = 125
                    with (evidence / ('debug_launch_' + arch + '.log')).open('ab') as stream:
                        stream.write(('owned cleanup failure: ' + type(exc).__name__ + '\n').encode())
            xcresult = root / ('runtime-' + arch + '.xcresult')
            target = evidence / ('xcresult-' + arch + '.tar.gz')
            if xcresult.is_dir() and not target.exists():
                try:
                    measurements[arch] = pack_directory(xcresult, target)
                except Exception as exc:
                    measurements[arch] = dict(error=type(exc).__name__, complete=False)
        if release.is_dir() and not (evidence / 'release-evidence.tar.gz').exists():
            names = {p.name for p in release.iterdir() if p.is_file() and
                (p.name.endswith(('.log', '.txt', '.diff', '.json', '.png')))}
            if names:
                try:
                    measurements['release-evidence-partial'] = pack_directory(release, evidence / 'release-evidence.tar.gz', names=names)
                except Exception as exc:
                    measurements['release-evidence-partial'] = dict(error=type(exc).__name__, complete=False)
        bridge.write_json(evidence / 'archive-sizes.json', dict(provisional_bounds=True,
            aggregate_cap=MAX_RETURN, member_cap=MAX_MEMBER, archives=measurements))
        (root / 'reconstruct.tar').unlink(missing_ok=True)
    return results


def payload_inventory(path):
    """Complete ZIP inventory; safe framework links and matched AppleDouble only."""
    records, total, names = [], 0, set()
    with zipfile.ZipFile(path) as archive:
        for item in archive.infolist():
            name = item.filename.rstrip('/')
            parts = name.split('/')
            require(name and not name.startswith('/') and '\\' not in name
                    and all(p not in ('', '.', '..') for p in parts) and name not in names,
                    'payload_path')
            names.add(name)
            mode = item.external_attr >> 16
            kind = stat.S_IFMT(mode)
            require(not mode & 0o7000 and kind in (0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK), 'payload_type')
            require(not item.flag_bits & 1 and item.file_size <= MAX_MEMBER, 'payload_size')
            total += item.file_size
            require(total <= MAX_RETURN and len(records) < MAX_ENTRIES, 'payload_size')
            metadata = parts[0] == '__MACOSX'
            require(parts[0] == 'Carbonic.app' or metadata, 'payload_top_level')
            lowered = name.casefold()
            require(not any(p.casefold() in ('.git', '.carbonic', 'source', 'evidence', 'logs') for p in parts)
                and not any(s in lowered for s in ('.xctest', '.xcresult', '.dsym', 'kernel_blob.bin',
                    'vm_snapshot_data', 'isolate_snapshot_data'))
                and not lowered.endswith(('.dart', '.swift', '.m', '.mm', '.c', '.cc', '.key', '.pem', '.log')),
                'payload_private')
            data = archive.read(item)
            require(b'-----BEGIN PRIVATE KEY-----' not in data and b'-----BEGIN RSA PRIVATE KEY-----' not in data,
                    'payload_private')
            target = data.decode('utf-8') if kind == stat.S_IFLNK else None
            if target is not None:
                require(not metadata and not target.startswith('/') and '\\' not in target, 'payload_link')
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
                require(resolved.startswith('Carbonic.app/') and '.framework/' in name, 'payload_link')
            records.append(dict(name=item.filename, type='symlink' if target is not None else
                ('directory' if item.is_dir() else 'file'), bytes=item.file_size, mode=mode,
                target=target, sha256=bridge.digest(data)))
        for record in records:
            name = record['name'].rstrip('/')
            if name.startswith('__MACOSX/') and record['type'] != 'directory':
                parts = name.split('/')[1:]
                require(parts[-1].startswith('._'), 'appledouble_member')
                parts[-1] = parts[-1][2:]
                require('/'.join(parts) in names and archive.read(record['name'])[:4] == b'\x00\x05\x16\x07',
                        'appledouble_member')
            if record['type'] == 'symlink':
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), record['target']))
                # Resolve chains without extracting; reject dangling or cyclic aliases.
                seen = {name}
                while True:
                    require(resolved not in seen, 'payload_link')
                    seen.add(resolved)
                    aliases = [r for r in records if r['type'] == 'symlink' and
                               (resolved == r['name'] or resolved.startswith(r['name'] + '/'))]
                    if not aliases:
                        require(resolved in names or any(n.startswith(resolved + '/') for n in names), 'payload_link')
                        break
                    link = max(aliases, key=lambda r: len(r['name']))
                    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(link['name']),
                        link['target'], resolved[len(link['name']):].lstrip('/')))
                    require(resolved.startswith('Carbonic.app/'), 'payload_link')
    require(records, 'payload_empty')
    return records


def validate_evidence_archive(data, measurement, *, collect=False):
    total, count, seen, members = 0, 0, set(), {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for item in archive:
            parts = item.name.split('/')
            require(item.isreg() and not item.pax_headers and not item.name.startswith('/')
                and all(p not in ('', '.', '..', '.git', '.carbonic') for p in parts)
                and '\\' not in item.name and item.name not in seen and not item.mode & 0o7000,
                'evidence_inventory')
            total += item.size
            count += 1
            require(item.size <= MAX_MEMBER and total <= MAX_RETURN and count <= MAX_ENTRIES, 'evidence_size')
            seen.add(item.name)
            # Force full decompression and integrity verification, without extraction.
            stream = archive.extractfile(item)
            if collect:
                members[item.name] = stream.read()
            else:
                while stream.read(1024 * 1024):
                    pass
    require(count == measurement.get('entries') and total == measurement.get('uncompressed_bytes')
            and count > 0, 'archive_measurements')
    return members


def bound_result(files, receipt):
    require(len(files['evidence/result.json']) <= bridge.MAX_JSON, 'result_size')
    result = json.loads(files['evidence/result.json'])
    bridge.binding(result, receipt['binding'])
    require(result.get('schema') == 'native-production.result.v1', 'native_protocol')
    expected = {n: dict(bytes=len(d), sha256=bridge.digest(d)) for n, d in files.items() if n != 'evidence/result.json'}
    require(result.get('outputs') == expected, 'output_hashes')
    return result


def verify_return(files, receipt, run, identity):
    require(run.get('conclusion') == 'success' and identity.get('outcome') == 'success', 'terminal_outcome')
    result = bound_result(files, receipt)
    require(result.get('schema') == 'native-production.result.v1' and result.get('protocol') == 'ok'
            and result.get('outcome') == 'success' and result.get('native_failed') is False, 'native_protocol')
    require(set(result.get('native', {})) == set(STEPS) and all(type(c) is int and c == 0
        for c in result['native'].values()), 'native_checks')
    expected = {n: dict(bytes=len(d), sha256=bridge.digest(d)) for n, d in files.items() if n != 'evidence/result.json'}
    require(result.get('outputs') == expected, 'output_hashes')
    required = {'products/' + n for n in PRODUCTS} | {'evidence/' + n for n in EVIDENCE if not n.endswith('.log')} | {'evidence/' + n + '.log' for n in COMMAND_STEPS}
    require(required <= files.keys(), 'return_missing')
    require(set(result.get('probes', {})) == set(bridge.PROBE_NAMES) and all(type(c) is int and c == 0
            for c in result['probes'].values()), 'tool_probes')
    require(all(files.get('evidence/' + n + '.log', b'').strip() for n in bridge.PROBE_NAMES), 'tool_probe_logs')
    require(files.get('evidence/openssl.log', b'').startswith(b'OpenSSL 3.'), 'openssl_receipt')
    source = json.loads(files['evidence/source-receipt.json'])
    require(source.get('source') == SOURCE and source.get('parity') == 'passed', 'production_source')
    bridge.binding(source['binding'], receipt['binding'])
    frozen = json.loads(files['evidence/release-frozen.json'])
    require(frozen == {n: expected['products/' + n] for n in PRODUCTS}, 'release_changed')
    for arch in ('arm64', 'x86_64'):
        summary = xctest_summary(files['evidence/xctest-results-' + arch + '.json'])
        require(summary['passedTests'] >= len(NATIVE_TESTS), 'xctest_coverage')
        xctest_cases(files['evidence/xctest-tests-' + arch + '.json'])
    sizes = json.loads(files['evidence/archive-sizes.json'])
    require(sizes.get('aggregate_cap') == MAX_RETURN and sizes.get('member_cap') == MAX_MEMBER
            and set(sizes.get('archives', {})) == {'release-evidence', 'arm64', 'x86_64'}, 'archive_measurements')
    for label, name in [('release-evidence', 'release-evidence.tar.gz'),
                        ('arm64', 'xcresult-arm64.tar.gz'), ('x86_64', 'xcresult-x86_64.tar.gz')]:
        data = files['evidence/' + name]
        require(sizes['archives'][label].get('archive_bytes') == len(data)
                and sizes['archives'][label].get('sha256') == bridge.digest(data), 'archive_measurements')
        members = validate_evidence_archive(data, sizes['archives'][label], collect=label == 'release-evidence')
        if label == 'release-evidence':
            release_evidence(members, json.loads(files['products/manifest.json']))
    return result
