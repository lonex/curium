defmodule Curium.KeystoreTest do
  use ExUnit.Case
  alias Curium.Keystore

  test "keystore initialization" do
    target_keystore = %Curium.Keystore{
      seed:
        "frame verb romance token replace crime thing behave stick scale trigger loyal lion basic broccoli fetch cargo",
      type: "bip32",
      passphrase: "abc",
      xpriv:
        "xprv9s21ZrQH143K4H6TqCCNNf9c25WeYwRBhArc5S4FzYQ6YqRtdZs71V7RcuqotXGDY1sXNmDtajtiGzRHqrmCGH7BBD1a7zPSBERtzUvio74",
      xpub:
        "xpub661MyMwAqRbcGmAvwDjNjo6La7M8xQ934PnCspTsYsw5Rdm3B7BMZHRuUCHwuMhKFVyBJapKQ8BSJ5bsJ4aGvCUainmPTPkyXdnFHwresMS"
    }

    keystore =
      Keystore.new_from_seed(
        Map.fetch!(target_keystore, :seed),
        Map.fetch!(target_keystore, :passphrase)
      )

    assert keystore == target_keystore
  end
end
