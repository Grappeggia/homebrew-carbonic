# Carbonic

Carbonic is a prototype macOS app for local device acquisition and session export.
This repository hosts the Homebrew cask and downloadable app builds; the app source
is maintained separately.

The first prototype release is being prepared. Once published, install with:

```sh
brew install --cask grappeggia/carbonic/carbonic
open -a Carbonic
```

Update with `brew upgrade --cask grappeggia/carbonic/carbonic`.
Uninstall with `brew uninstall --cask carbonic`; recorded sessions are retained.

Prototype builds are not Apple-notarized. macOS may request explicit first-launch
approval in System Settings > Privacy & Security. The cask preserves normal macOS
security handling. These releases are for prototyping; physical-device and
long-duration qualification remain pending.
