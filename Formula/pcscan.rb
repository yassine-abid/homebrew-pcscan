class Pcscan < Formula
  desc "Read-only defensive PC health, security & investigation scanner"
  homepage "https://github.com/yassine-abid/homebrew-pcscan"
  url "https://github.com/yassine-abid/homebrew-pcscan/archive/refs/tags/v1.1.0.tar.gz"
  sha256 "01f6d1803af4c56ba615d5a576d974c8dd544287f6a31e039ed97cff848ce39b"
  version "1.1.0"

  depends_on "clamav"

  def install
    bin.install "pcscan.sh" => "pcscan"
  end

  test do
    assert_match "pcscan", shell_output("#{bin}/pcscan --help")
  end
end
