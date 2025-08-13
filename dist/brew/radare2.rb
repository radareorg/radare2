class Radare2 < Formula
  desc "Reverse engineering framework"
  homepage "https://radare.org"
  url "https://github.com/radareorg/radare2/archive/refs/tags/6.0.0.tar.gz"
  sha256 "023d75b0dca8770bbc9be5a569147599eb1a6d52017bba5ea22e5eca7c4e1075"
  license "LGPL-3.0-only"
  head "https://github.com/radareorg/radare2.git", branch: "master"

  livecheck do
    url :stable
    regex(/^v?(\d+(?:\.\d+)+)$/i)
  end

  bottle do
    sha256 arm64_sequoia: "bf591e10a781b44174c298af254633413dff5084058fb742c114f239e02e321d"
    sha256 arm64_sonoma:  "0860f54632b39db0b3b1d4f7dd669d86fe0b4d01ce889a8bd3ef8e7de23affc2"
    sha256 arm64_ventura: "ec9ab2e5df92485c5be38955c7889494be0c6f3edfa85c6a1f0d63e6297e3e7e"
    sha256 sonoma:        "e4249fc9b7b80c8d891d2a7a444758d78c516bd3f451c83c381c84a2fc6c9c81"
    sha256 ventura:       "2846fab86e7c4f82508ee02ab955aaabddd6be27b914da7695b93d422c13cf8b"
    sha256 arm64_linux:   "060ccda362ca5da9da51c94712728662cfac54f178afdd068acd0d65947c524d"
    sha256 x86_64_linux:  "f7b46599711c709e805f147b42dd507aeb7aeab505bea4c1b11b6aa35bdeef34"
  end

  def install
    system "./configure", "--prefix=#{prefix}"
    system "make"
    system "make", "install"
  end

  test do
    assert_match "radare2 #{version}", shell_output("#{bin}/r2 -v")
  end
end
