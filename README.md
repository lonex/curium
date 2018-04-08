# Curium

Electrum compatible Seed and key derivation basics.

## Example usage in IEx

```elixir
iex(1)> seed_words = Curium.Mnemonic.gen_seed()
"glare canoe topic laptop grant waste winter cage silver gift link alarm"
iex(2)> seed_words = Curium.Mnemonic.gen_seed() # another set of Mnemonic seed words
"harvest switch early crazy bean joy radar deal music injury mechanic actress"
iex(3)> ks = Curium.Keystore.new_from_seed(seed_words, "awesome")
%Curium.Keystore{
  passphrase: "awesome",
  seed: "harvest switch early crazy bean joy radar deal music injury mechanic actress",
  type: "bip32",
  xpriv: "xprv9s21ZrQH143K3VsAyQmSpzMrY4bHvw16UVCdCyXpWzBbJi4Gb1WxgzCoKsbUnUqWABWPTAHEttykXjAhp28ms1M4BszukkVoGWUmU1LSxgs",
  xpub: "xpub661MyMwAqRbcFywe5SJTC8Jb66RnLPiwqi8E1MwS5KiaBWPR8YqDEnXHB8cp9dPVPTS7bcss5vcoQAWirH4wSnxgfafHntZudzRHny2xNkY"
}
# key derivation
iex(4)> {:ok, seed} = Curium.Mnemonic.mnemonic_to_seed(seed_words, "awesome")
{:ok,
 <<152, 112, 40, 4, 253, 133, 114, 122, 104, 170, 118, 179, 98, 105, 105, 62,
   13, 254, 67, 95, 36, 156, 133, 123, 233, 34, 57, 157, 1, 80, 145, 8, 176,
   149, 1, 109, 163, 64, 88, 104, 81, 57, 54, 119, 31, 119, 107, 174, ...>>}
iex(5)> {xpriv, xpub} = Curium.BIP32.bip32_master_privkey_pubkey(seed, "standard")
{"xprv9s21ZrQH143K3VsAyQmSpzMrY4bHvw16UVCdCyXpWzBbJi4Gb1WxgzCoKsbUnUqWABWPTAHEttykXjAhp28ms1M4BszukkVoGWUmU1LSxgs",
 "xpub661MyMwAqRbcFywe5SJTC8Jb66RnLPiwqi8E1MwS5KiaBWPR8YqDEnXHB8cp9dPVPTS7bcss5vcoQAWirH4wSnxgfafHntZudzRHny2xNkY"}
iex(6)> {xpriv, xpub} = Curium.BIP32.bip32_privkey_derivation(xpriv, "m", "m/0'")
{"xprv9vRGzoLjpQz2WjihacLpKyqq3iW8NyVtorEC9YyfnYnG6zzDeXJihiQKho5xKHAtKwQMAfmrBUctvyKjFpk79Z9XTz3ZdKP9YcmafH3tHNr",
 "xpub69QdQJsdenYKjDoAgdsph7nZbkLcnSDkB59nwwPHLtKEyoKNC4cyFWioZ3Qf4Z9wp3nuC8Wc3oumY6fw7dadyYrahbgqhe4T1RTVXZRteRY"}
iex(7)> {xpriv, xpub} = Curium.BIP32.bip32_privkey_derivation(xpriv, "m/0'", "m/0'/1/2'/2/1000000000")
{"xprvA3MjP2CXgGGUtu5Njrp6z4AHdVYWfiMu6kDEXW4wmJ45kKAJuCPiK75QUWT1kDeVZrQbuGbAU7VAnDEiicUZiAuk8T987h6ubgTr1qzn2bQ",
 "xpub6GM5nXjRWdpn7P9qqtM7MC72BXP15B5kTy8qKtUZKdb4d7VTSjhxruPtKkrc57yvhGKLLFTBt9Y3Hxwh5ZMwchQxwZex7rKAUwAxL9x9AJ8"}
```

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `curium` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:curium, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/curium](https://hexdocs.pm/curium).

