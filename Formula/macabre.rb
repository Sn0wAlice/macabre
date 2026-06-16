class Macabre < Formula
  desc "macOS hardening & security audit scanner"
  homepage "https://github.com/Sn0wAlice/macabre"
  version "0.1.1"
  license "MIT"

  depends_on :macos

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Sn0wAlice/macabre/releases/download/v#{version}/macabre-darwin-arm64.tar.gz"
      sha256 "7dfa5bfd48d51c81c0610c0354885d766158c510eceb3139cad703a2f87b1015"
    else
      url "https://github.com/Sn0wAlice/macabre/releases/download/v#{version}/macabre-darwin-amd64.tar.gz"
      sha256 "fc8e687ab55f8a4b8ff91e56608575dc4b20c7478cc4aecebb68f9d3732e5b4d"
    end
  end

  def install
    bin.install "macabre"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/macabre --version")
  end
end
