defmodule Curium.BIP32Test do
  use ExUnit.Case
  alias Curium.BIP32

  test "derive the master priv and public key from seed" do
    seed =
      <<238, 147, 46, 5, 187, 73, 228, 200, 85, 13, 110, 91, 182, 110, 150, 48, 79, 222, 14, 254,
        38, 38, 29, 142, 228, 125, 119, 224, 100, 101, 100, 201, 83, 206, 98, 172, 107, 3, 70,
        239, 75, 20, 238, 83, 19, 155, 237, 31, 215, 236, 121, 223, 255, 113, 193, 221, 48, 239,
        153, 56, 203, 159, 75, 126>>

    assert BIP32.bip32_master_privkey_pubkey(seed) ==
             {"xprv9s21ZrQH143K26wrD6L7Z8v3a7dn8EB3HtGqKCa11qe8BcPXBeUm7YbCjMbnAxC2VKkD7bDcDoxqYX1eF8kmQELTwNLJiVDse9LZhG2hLuH",
              "xpub661MyMwAqRbcEb2KK7s7vGrn89UGXgttf7CS7aycaBB74QifjBo1fLugagGr7n4RzDrPpAfaSjGSvHnF9KS5xWpzogZUo9WApizspFCrYRP"}
  end

  test "private child key derivation returns correct private key and chaincode" do
    key =
      <<232, 243, 46, 114, 61, 236, 244, 5, 26, 239, 172, 142, 44, 147, 201, 197, 178, 20, 49, 56,
        23, 205, 176, 26, 20, 148, 185, 23, 200, 67, 107, 53>>
      |> :binary.bin_to_list()

    chaincode =
      <<135, 61, 255, 129, 192, 47, 82, 86, 35, 253, 31, 229, 22, 126, 172, 58, 85, 160, 73, 222,
        61, 49, 75, 180, 46, 226, 39, 255, 237, 55, 213, 8>>
      |> :binary.bin_to_list()

    # 2 ^ 31
    i = 2_147_483_648

    assert BIP32.ckd_priv(key, chaincode, i) == {
             <<237, 178, 225, 79, 158, 231, 125, 38, 221, 147, 180, 236, 237, 232, 209, 110, 212,
               8, 206, 20, 155, 108, 216, 11, 7, 21, 162, 217, 17, 160, 175, 234>>
             |> :binary.bin_to_list(),
             <<71, 253, 172, 189, 15, 16, 151, 4, 59, 120, 198, 60, 32, 195, 78, 244, 237, 154,
               17, 29, 152, 0, 71, 173, 22, 40, 44, 122, 230, 35, 97, 65>>
             |> :binary.bin_to_list()
           }
  end

  @doc """
  returns 
   {"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
   "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"}
  """
  def master_privkey_pubkey() do
    seed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    BIP32.bip32_master_privkey_pubkey(seed, "standard")
  end

  defp bip32_drivation_and_asserts(_, [], xpriv, xpub), do: {xpriv, xpub}

  defp bip32_drivation_and_asserts(branch, [sub_branch | rest], xpriv, xpub) do
    sequence = branch <> "/" <> sub_branch

    is_hardened = String.at(sub_branch, -1) == "'"

    xpub2 =
      unless is_hardened do
        BIP32.bip32_pubkey_derivation(xpub, branch, sequence)
      end

    {xpriv, xpub} = BIP32.bip32_privkey_derivation(xpriv, branch, sequence)

    unless is_hardened do
      assert xpub == xpub2
    end

    bip32_drivation_and_asserts(sequence, rest, xpriv, xpub)
  end

  test "step by step private public key derivation, case 1" do
    seed = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    {xpriv, xpub} = BIP32.bip32_master_privkey_pubkey(seed, "standard")
    sequence = "m/0'/1/2'/2/1000000000"
    {[branch], rest} = String.split(sequence, "/") |> Enum.split(1)
    {xpriv, xpub} = bip32_drivation_and_asserts(branch, rest, xpriv, xpub)

    assert {xpriv, xpub} == {
             "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
             "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
           }
  end

  test "step by step private public key derivation, case 2" do
    seed =
      "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
      |> Exbtc.Core.changebase(16, 256)

    {xpriv, xpub} = BIP32.bip32_master_privkey_pubkey(seed, "standard")
    sequence = "m/0/2147483647'/1/2147483646'/2"
    {[branch], rest} = String.split(sequence, "/") |> Enum.split(1)
    {xpriv, xpub} = bip32_drivation_and_asserts(branch, rest, xpriv, xpub)

    assert {xpriv, xpub} == {
             "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
             "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
           }
  end

  test "bip32 private child key derivation" do
    {xpriv, _xpub} = master_privkey_pubkey()

    assert BIP32.bip32_privkey_derivation(
             xpriv,
             "m",
             "m/0'"
           ) ==
             {"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
              "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"}
  end

  test "bip32 public child key derivation" do
    {_xpriv, xpub} = master_privkey_pubkey()

    assert BIP32.bip32_pubkey_derivation(
             xpub,
             "m/",
             "m/1"
           ) ==
             "xpub68Gmy5EVb2BdHTYHpekwGdcbBWax19w9HwA2DaADYvuCSSgt4YAErxxSN1KWSnmyqkwRNbnTj3XiUBKmHeC8rTjLRPjSULcDKQQgfgJDppq"
  end
end
