class Macabre < Formula
  desc "macOS hardening & security audit scanner"
  homepage "https://github.com/Sn0wAlice/macabre"
  version "0.1.0"
  license "MIT"

  depends_on :macos

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Sn0wAlice/macabre/releases/download/v#{version}/macabre-darwin-arm64.tar.gz"
      sha256 "9cfa6c7988024c13af5c7faf20a2bad2e9e10f95b563b4badb5561606c68d39d"
    else
      url "https://github.com/Sn0wAlice/macabre/releases/download/v#{version}/macabre-darwin-amd64.tar.gz"
      sha256 "13a7f0420c1bc9559534b0f594983d0d057248df0c272d0b42309a9077cde7c8"
    end
  end

  def install
    bin.install "macabre"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/macabre --version")
  end
end
