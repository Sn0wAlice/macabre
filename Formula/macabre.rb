# This formula is regenerated automatically by .github/workflows/release.yml
# on every tagged release (version + sha256 are filled in from the built
# artifacts). The placeholder sha256 values below are only valid once a release
# with matching binaries exists.
class Macabre < Formula
  desc "macOS hardening & security audit scanner"
  homepage "https://github.com/Sn0wAlice/macabre"
  version "0.1.0"
  license "MIT"

  depends_on :macos

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Sn0wAlice/macabre/releases/download/v#{version}/macabre-darwin-arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/Sn0wAlice/macabre/releases/download/v#{version}/macabre-darwin-amd64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "macabre"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/macabre --version")
  end
end
