# Homebrew Formula for whiff
#
# Copy to your tap as Formula/whiff.rb and fill sha256 from Release SHA256SUMS.
class Whiff < Formula
  desc "Describe any file as one JSON document for people and LLMs"
  homepage "https://github.com/baoulo/whiff"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/baoulo/whiff/releases/download/v#{version}/whiff-v#{version}-macos-aarch64.tar.gz"
      # sha256 "REPLACE_AFTER_RELEASE"
    end
    on_intel do
      url "https://github.com/baoulo/whiff/releases/download/v#{version}/whiff-v#{version}-macos-x86_64.tar.gz"
      # sha256 "REPLACE_AFTER_RELEASE"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/baoulo/whiff/releases/download/v#{version}/whiff-v#{version}-linux-aarch64.tar.gz"
      # sha256 "REPLACE_AFTER_RELEASE"
    end
    on_intel do
      url "https://github.com/baoulo/whiff/releases/download/v#{version}/whiff-v#{version}-linux-x86_64.tar.gz"
      # sha256 "REPLACE_AFTER_RELEASE"
    end
  end

  def install
    bin.install "whiff"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/whiff --version")
  end
end
