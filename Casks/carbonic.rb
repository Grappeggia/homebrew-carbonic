cask "carbonic" do
  version "0.1.1,2"
  sha256 "e29b2c5cce855f7ab4a9f3cdc707ef1a0a8c6e3b9a31174c6d90c8a8d60d0be1"

  url "https://github.com/Grappeggia/homebrew-carbonic/releases/download/v#{version.csv.first}-#{version.csv.second}/Carbonic-#{version.csv.first}-#{version.csv.second}-macos-universal2.zip"
  name "Carbonic"
  desc "Local biosignal acquisition and session recording"
  homepage "https://github.com/Grappeggia/homebrew-carbonic"

  depends_on macos: :sonoma

  app "Carbonic.app"

  uninstall quit: "org.carbonic.carbonicapp"

  caveats <<~EOS
    Prototype: ad-hoc signed, not Developer ID signed or notarized.
    macOS may block the first launch. After reviewing the source and checksum,
    use System Settings > Privacy & Security > Open Anyway to approve it.
    Recordings are retained when this cask is uninstalled.
  EOS
end
