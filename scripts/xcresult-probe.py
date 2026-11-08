"""Generic nonsensitive XCTest/xcresult CLI schema probe; no Carbonic source."""
import json
import os
from pathlib import Path
import subprocess

root = Path.cwd() / 'build/xcresult-schema-probe'
root.mkdir(parents=True)
(root / 'tmp').mkdir()
env = {k: v for k, v in os.environ.items() if k in ('PATH', 'HOME', 'LANG', 'DEVELOPER_DIR', 'SDKROOT')}
(root / 'cache').mkdir()
(root / 'cache/clang').mkdir()
(root / 'cache/swiftpm').mkdir()
env.update(XDG_CACHE_HOME=str(root / 'cache'), CLANG_MODULE_CACHE_PATH=str(root / 'cache/clang'),
           SWIFTPM_MODULECACHE_OVERRIDE=str(root / 'cache/swiftpm'), TMPDIR=str(root / 'tmp'), TMP=str(root / 'tmp'), TEMP=str(root / 'tmp'))
outputs = root / 'outputs'
outputs.mkdir()
receipts = []
def run(label, argv, cwd=root):
    with (outputs / (label + '.stdout')).open('wb') as out, (outputs / (label + '.stderr')).open('wb') as err:
        try:
            code = subprocess.run(argv, cwd=cwd, env=env, stdout=out, stderr=err, timeout=240).returncode
        except subprocess.TimeoutExpired:
            code = 124
    receipts.append(dict(label=label, argv=argv, exit=code))
    (outputs / 'commands.json').write_text(json.dumps(receipts, indent=2))
    return code
run('xcode-version', ['xcodebuild', '-version'])
run('xcresult-help', ['xcrun', 'xcresulttool', '--help'])
run('test-results-help', ['xcrun', 'xcresulttool', 'get', 'test-results', '--help'])
for sub in ('summary', 'tests'):
    run(sub + '-help', ['xcrun', 'xcresulttool', 'get', 'test-results', sub, '--help'])
run('schema-help', ['xcrun', 'xcresulttool', 'formatDescription', '--help'])
run('legacy-schema', ['xcrun', 'xcresulttool', 'formatDescription', 'get', '--format', 'json'])
package = root / 'SchemaProbe'
(package / 'Sources/SchemaProbe').mkdir(parents=True)
(package / 'Tests/SchemaProbeTests').mkdir(parents=True)
(package / 'Package.swift').write_text('''// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "SchemaProbe", products: [.library(name: "SchemaProbe", targets: ["SchemaProbe"])], targets: [.target(name: "SchemaProbe"), .testTarget(name: "SchemaProbeTests", dependencies: ["SchemaProbe"])])
''')
(package / 'Sources/SchemaProbe/SchemaProbe.swift').write_text('public let probeValue = 1\n')
(package / 'Tests/SchemaProbeTests/ProbeTests.swift').write_text('''import XCTest
@testable import SchemaProbe
final class ProbeTests: XCTestCase {
 func testPass() { XCTAssertEqual(probeValue, 1) }
 func testSkip() throws { throw XCTSkip("generic schema probe skip") }
 func testFail() { XCTFail("generic expected schema probe failure") }
}
''')
run('list', ['xcodebuild', '-list', '-json'], cwd=package)
listing = json.loads((outputs / 'list.stdout').read_bytes())
schemes = listing.get('workspace', listing.get('project', {})).get('schemes', [])
if len(schemes) != 1:
    raise RuntimeError('probe expects exactly one generated package scheme')
base = ['xcodebuild', 'test', '-scheme', schemes[0], '-destination', 'platform=macOS', 'CODE_SIGN_IDENTITY=-']
results = []
for label, selection in [('pass-skip', '-skip-testing:SchemaProbeTests/ProbeTests/testFail'), ('expected-fail', '-only-testing:SchemaProbeTests/ProbeTests/testFail')]:
    bundle = root / (label + '.xcresult')
    code = run(label, [*base, '-derivedDataPath', str(root / ('derived-' + label)), '-resultBundlePath', str(bundle), selection], cwd=package)
    results.append((label, code))
    for sub in ('summary', 'tests'):
        argv = ['xcrun', 'xcresulttool', 'get', 'test-results', sub, '--path', str(bundle)]
        run(label + '-' + sub, argv)
        run(label + '-' + sub + '-format-json', [*argv, '--format', 'json'])
        run(label + '-' + sub + '-schema', [*argv, '--schema'])
(outputs / 'expected-results.json').write_text(json.dumps(dict(results=dict(results), probe_valid=results == [('pass-skip', 0), ('expected-fail', 65)]), indent=2))
# A failed assertion is intentional; every diagnostic is uploaded by always().
raise SystemExit(results[-1][1] or 1)
