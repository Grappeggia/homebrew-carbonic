# Carbonic for macOS

Carbonic records biosignal sessions locally on macOS 14 Sonoma and later,
on Apple silicon and Intel Macs. This is a prototype distribution.

Current scope: connection/contact monitoring, local session recording, history,
export and basic raw acquisition status.

```bash
brew tap grappeggia/carbonic
brew trust --cask grappeggia/carbonic/carbonic
brew install --cask grappeggia/carbonic/carbonic
```

Homebrew 7 requires explicit trust before loading a third-party cask's definition.
The trust command above approves only this cask. Review its pinned checksum and
definition before trusting it. This is separate from macOS first-launch approval.

The application is ad-hoc signed for local integrity. It is **not Developer ID
signed or notarized by Apple**. macOS can block the first launch. After reviewing
the checksum and deciding to trust the prototype, open System Settings → Privacy
& Security and use Open Anyway, then approve the normal macOS prompt. The cask
preserves macOS quarantine and first-launch protections.

```bash
brew upgrade --cask grappeggia/carbonic/carbonic
brew uninstall --cask grappeggia/carbonic/carbonic
```

Uninstall quits Carbonic and removes the application; recordings remain on disk.
No `zap` operation is configured. Bluetooth access still needs your permission.

Release assets include the universal application archive and a manifest with its
SHA-256, size, source commit, version, bundle ID, architecture inventory, and
prototype signing status. Verify a downloaded archive using `shasum -a 256` and
compare it with the release manifest and pinned cask checksum.

This custom tap distributes compiled artifacts only. The application's source
repository is private. This tap is not a submission to the official Homebrew
cask repository. Physical Bluetooth qualification and long endurance testing
remain separate from installation and packaging checks.

Hosted-runner screenshots have a pre-existing text rendering limitation. Physical
Mac rendering, Bluetooth/contact qualification and long endurance testing remain
pending. Packaging smoke results do not establish those physical qualifications.
