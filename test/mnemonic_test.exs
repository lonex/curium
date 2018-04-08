defmodule Curium.MnemonicTest do
  use ExUnit.Case
  alias Curium.Mnemonic

  test "encode should work" do
    assert Mnemonic.encode(
             26_563_230_048_437_957_592_232_553_826_663_696_440_606_756_685_920_117_476
           ) ==
             "frame verb romance token replace crime thing behave stick scale trigger loyal lion basic broccoli fetch cargo"
  end

  test "mnemonic_to_seed matches" do
    assert Mnemonic.mnemonic_to_seed("abc", "passphrase") ==
             {:ok,
              <<238, 147, 46, 5, 187, 73, 228, 200, 85, 13, 110, 91, 182, 110, 150, 48, 79, 222,
                14, 254, 38, 38, 29, 142, 228, 125, 119, 224, 100, 101, 100, 201, 83, 206, 98,
                172, 107, 3, 70, 239, 75, 20, 238, 83, 19, 155, 237, 31, 215, 236, 121, 223, 255,
                113, 193, 221, 48, 239, 153, 56, 203, 159, 75, 126>>}
  end
end
