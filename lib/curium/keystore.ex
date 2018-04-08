defmodule Curium.Keystore do
  @moduledoc """
  BIP keystore
  """
  # list of integers
  @type seed_as_byte_list :: list(byte)
  @type t :: struct

  alias __MODULE__
  alias Curium.Mnemonic
  alias Curium.BIP32

  # XXX only supports "standard" now. 
  @xtype "standard"
  @der "m/"

  @type_imported "imported"
  @type_hardware "hardware"
  @type_bip32 "bip32"

  defstruct(
    xpub: nil,
    xpriv: nil,
    seed: nil,
    passphrase: nil,
    type: @type_bip32
  )

  @spec new_from_seed(String.t(), String.t()) :: t
  def new_from_seed(seed_words, passphrase) do
    ks = %Keystore{seed: seed_words, passphrase: passphrase}
    {:ok, bip32_seed} = Mnemonic.mnemonic_to_seed(seed_words, passphrase)
    add_xpriv_from_seed(ks, bip32_seed, @xtype, @der)
  end

  @spec add_xpriv_from_seed(t, Mnemonic.seed(), String.t(), String.t()) :: t
  def add_xpriv_from_seed(keystore, seed, xtype, derivation) do
    {xpriv, _} = BIP32.bip32_master_privkey_pubkey(seed, xtype)
    {xpriv, xpub} = BIP32.bip32_privkey_derivation(xpriv, @der, derivation)
    %{keystore | xpub: xpub, xpriv: xpriv}
  end
end
