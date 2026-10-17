# Homebrew Formula for whiff
#
class Whiff < Formula
  desc "Describe any file as one JSON document for people and LLMs"
  homepage "https://github.com/baoulo/whiff"
  version "0.2.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/baoulo/whiff/releases/download/v#{version}/whiff-v#{version}-macos-aarch64.tar.gz"
      sha256 "fb2587d816ab64459e3beb400dd8d5aee0dc759705ae888ddc22ba08a69ad109"
    end
    on_intel do
      url "https://github.com/baoulo/whiff/releases/download/v#{version}/whiff-v#{version}-macos-x86_64.tar.gz"
      sha256 "d42b2525f50ed4b6fd91cdbccb806655a3fdef3e73085e4981c1a63b910782af"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/baoulo/whiff/releases/download/v#{version}/whiff-v#{version}-linux-aarch64.tar.gz"
      sha256 "2ee62c383b34adef21eaa661b7179e24ca6db3bb0b37967085179df62121b3b8"
    end
    on_intel do
      url "https://github.com/baoulo/whiff/releases/download/v#{version}/whiff-v#{version}-linux-x86_64.tar.gz"
      sha256 "2752a29d78847832c490b27cc39fef9741cf4d950b5d0a2cfb9fcf3306733c10"
    end
  end

  def install
    bin.install "whiff"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/whiff --version")
  end
end
