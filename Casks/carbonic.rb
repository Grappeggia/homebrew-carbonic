cask "carbonic" do
  version "0.1.2,3"
  sha256 "f522ea041f807a6c414155550fbf04609d6e2d6e873b5ce172b9a45ed3deae9c"

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
