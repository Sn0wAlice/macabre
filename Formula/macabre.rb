class Macabre < Formula
  desc "macOS hardening & security audit scanner"
  homepage "https://github.com/Sn0wAlice/macabre"
  version "0.1.2"
  license "MIT"

  depends_on :macos

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Sn0wAlice/macabre/releases/download/v#{version}/macabre-darwin-arm64.tar.gz"
      sha256 "8e283a0bbf543a6172f67c016bb052c394a6e832f60bb4a41a8a65debdb0ae12"
    else
      url "https://github.com/Sn0wAlice/macabre/releases/download/v#{version}/macabre-darwin-amd64.tar.gz"
      sha256 "fcab2f402a965f91fd9cb300fc3b5a1b666907ddfa0c85a14c4ec2e8a1b954ac"
    end
  end

  def install
    bin.install "macabre"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/macabre --version")
  end
end
