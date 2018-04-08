defmodule Curium.BIP32 do
  use Bitwise

  @type base58_encoded_private_key :: base58_encoded_string
  @type base58_encoded_public_key :: base58_encoded_string
  @type base58_encoded_string :: String.t()

  @type binary_private_key :: list(byte)
  @type binary_public_key :: list(byte)
  @type binary_compressed_pubkey :: list(byte)

  @type depth :: integer
  @type child_number :: integer
  @type index :: integer
  @type chaincode :: list(byte)
  @type fingerprint :: list(byte)

  @mainnet_private [4, 136, 173, 228]
  @mainnet_public [4, 136, 178, 30]
  @testnet_private [4, 53, 131, 148]
  @testnet_public [4, 53, 135, 207]
  @private [@mainnet_private, @testnet_private]
  @public [@mainnet_public, @testnet_public]

  @hardened_start 0x80000000

  def mainnet_private, do: @mainnet_private
  def mainnet_public, do: @mainnet_public

  alias Curium.U

  def xpriv_header(xtype) do
    case xtype do
      "standard" ->
        @mainnet_private

      _ ->
        raise "this type #{xtype} is not supported"
    end
  end

  def vbytes_xpriv_header(vbytes) do
    case vbytes do
      @mainnet_private ->
        "standard"

      _ ->
        raise "Unsupported vbytes #{vbytes}"
    end
  end

  def xpub_header(xtype) do
    case xtype do
      "standard" ->
        @mainnet_public

      _ ->
        raise "this type #{xtype} is not supported"
    end
  end

  def vbytes_xpub_header(vbytes) do
    case vbytes do
      @mainnet_public ->
        "standard"

      _ ->
        raise "Unsupported vbytes #{vbytes}"
    end
  end

  @spec bip32_privkey_derivation(base58_encoded_string(), String.t(), String.t()) ::
          {base58_encoded_private_key(), base58_encoded_public_key()}
  def bip32_privkey_derivation(xpriv, branch, sequence) when branch == sequence do
    {xpriv, xpub_from_xpriv(xpriv)}
  end

  @doc """
    branch matches the leading substring of sequence. e.g. branch = "m/", sequence = "m/0'/1"
  """
  @spec bip32_privkey_derivation(base58_encoded_private_key(), String.t(), String.t()) ::
          {base58_encoded_private_key(), base58_encoded_public_key()}
  def bip32_privkey_derivation(parent_xpriv, branch, sequence) do
    {vbytes, chaincode, key, depth, _fingerprint, _child_number} = deserialize_xpriv(parent_xpriv)

    branch =
      if String.ends_with?(branch, "/") do
        branch
      else
        branch <> "/"
      end

    {index, parent_key, key, chaincode, depth} =
      cont_key_chain_derivation(
        String.slice(sequence, String.length(branch)..-1),
        nil,
        parent_xpriv,
        key,
        chaincode,
        depth
      )

    parent_compressed_pubkey =
      Exbtc.Core.privkey_to_pubkey(parent_key) |> Exbtc.Core.decode_pubkey()
      |> Exbtc.Core.encode_pubkey("bin_compressed")

    fingerprint =
      Enum.slice(
        Exbtc.Core.bin_hash160(parent_compressed_pubkey),
        0..3
      )

    child_number = Exbtc.Core.encode(index, 256, 4)

    compressed_pubkey = privkey_to_bin_compressed_pubkey(key)

    {
      serialize_xpriv(
        xpriv_header(vbytes),
        chaincode,
        key,
        depth,
        fingerprint,
        child_number
      ),
      serialize_xpub(
        xpub_header(vbytes),
        chaincode,
        compressed_pubkey,
        depth,
        fingerprint,
        child_number
      )
    }
  end

  @spec bip32_pubkey_derivation(base58_encoded_public_key(), String.t(), String.t()) ::
          base58_encoded_public_key()
  def bip32_pubkey_derivation(parent_xpub, branch, sequence) do
    {vbytes, chaincode, pubkey, depth, _fingerprint, _child_number} =
      deserialize_xpub(parent_xpub)

    branch =
      if String.ends_with?(branch, "/") do
        branch
      else
        branch <> "/"
      end

    {index, parent_key, key, chaincode, depth} =
      cont_pubkey_chain_derivation(
        String.slice(sequence, String.length(branch)..-1),
        nil,
        parent_xpub,
        pubkey,
        chaincode,
        depth
      )

    fingerprint =
      Enum.slice(
        Exbtc.Core.bin_hash160(parent_key),
        0..3
      )

    child_number = Exbtc.Core.encode(index, 256, 4)

    serialize_xpub(
      xpub_header(vbytes),
      chaincode,
      key,
      depth,
      fingerprint,
      child_number
    )
  end

  @spec cont_pubkey_chain_derivation(
          String.t(),
          index(),
          binary_public_key(),
          binary_public_key(),
          chaincode(),
          depth()
        ) :: {index(), binary_public_key(), binary_public_key(), chaincode(), depth()}
  defp cont_pubkey_chain_derivation("", index, parent_key, key, chaincode, depth) do
    {index, parent_key, key, chaincode, depth}
  end

  defp cont_pubkey_chain_derivation(path, _index, _parent_key, key, chaincode, depth) do
    [curr, rest] =
      if String.contains?(path, "/") do
        String.split(path, "/", parts: 2)
      else
        [path, ""]
      end

    i = String.to_integer(curr)
    parent_key = key
    {key, chaincode} = ckd_pub(key, chaincode, i)
    depth = depth + 1
    cont_pubkey_chain_derivation(rest, i, parent_key, key, chaincode, depth)
  end

  def ckd_pub(key, chaincode, i) do
    if i &&& @hardened_start > 0, do: raise("Error in public key child key derivation")
    index_as_charlist = Exbtc.Core.encode(i, 256, 4)
    cap_i = :binary.bin_to_list(:crypto.hmac(:sha512, chaincode, key ++ index_as_charlist))

    pubkey =
      Exbtc.Core.fast_multiply(Exbtc.Core.g(), Enum.slice(cap_i, 0..31) |> Exbtc.Core.decode(256))

    {
      # add 2 pubkey points -> decode -> encode again with "bin_compressed"
      Exbtc.Core.add_pubkeys(
        pubkey |> Exbtc.Core.encode_pubkey("bin"),
        Exbtc.Core.decode_pubkey(key) |> Exbtc.Core.encode_pubkey("bin")
      )
      |> Exbtc.Core.decode_pubkey("bin")
      |> Exbtc.Core.encode_pubkey("bin_compressed"),
      Enum.slice(cap_i, 32..-1)
    }
  end

  @spec cont_key_chain_derivation(
          String.t(),
          child_number() | nil,
          binary_private_key(),
          binary_private_key() | nil,
          chaincode(),
          depth()
        ) :: {index(), binary_private_key(), binary_private_key(), chaincode(), depth()}
  defp cont_key_chain_derivation("", index, parent_key, key, chaincode, depth) do
    {index, parent_key, key, chaincode, depth}
  end

  defp cont_key_chain_derivation(path, _index, _parent_key, key, chaincode, depth) do
    [curr, rest] =
      if String.contains?(path, "/") do
        String.split(path, "/", parts: 2)
      else
        [path, ""]
      end

    i =
      if String.at(curr, -1) == "'" do
        @hardened_start + (String.trim_trailing(curr, "'") |> String.to_integer())
      else
        String.to_integer(curr)
      end

    parent_key = key
    {key, chaincode} = ckd_priv(key, chaincode, i)
    depth = depth + 1
    cont_key_chain_derivation(rest, i, parent_key, key, chaincode, depth)
  end

  @spec ckd_priv(binary_private_key(), chaincode(), child_number()) ::
          {base58_encoded_private_key(), chaincode()}
  def ckd_priv(key, chaincode, i) do
    hardened? = (i &&& @hardened_start) > 0
    # index_as_charlist: 4-bytes codepoint representation of the integer. e.g.
    # 64 -> [0, 0, 0, 64]
    # 0x80000001 -> [128, 0, 0, 0]
    index_as_charlist = Exbtc.Core.encode(i, 256, 4)
    compressed_pubkey = privkey_to_bin_compressed_pubkey(key)

    data =
      if hardened? do
        [0] ++ key ++ index_as_charlist
      else
        compressed_pubkey ++ index_as_charlist
      end

    cap_i =
      :binary.bin_to_list(
        :crypto.hmac(
          :sha512,
          chaincode,
          data
        )
      )

    {
      # child_key: sum of decoded integer, then encode list(byte) again
      Exbtc.Core.add_privkeys(
        Enum.slice(cap_i, 0..31) |> Exbtc.Core.decode(256),
        Exbtc.Core.decode(key, 256)
      )
      |> Exbtc.Core.encode(256),

      # child_chaincode
      Enum.slice(cap_i, 32..-1)
    }
  end

  @spec xpub_from_xpriv(base58_encoded_private_key()) :: base58_encoded_public_key()
  def xpub_from_xpriv(xpriv) do
    {vbytes, chaincode, key, depth, fingerprint, child_number} = deserialize_xpriv(xpriv)
    compressed_pubkey = privkey_to_bin_compressed_pubkey(key)

    serialize_xpub(
      xpub_header(vbytes),
      chaincode,
      compressed_pubkey,
      depth,
      fingerprint,
      child_number
    )
  end

  @spec bip32_master_privkey_pubkey(Curium.Keystore.seed_as_byte_list(), String.t()) ::
          {base58_encoded_private_key(), base58_encoded_public_key()}
  def bip32_master_privkey_pubkey(seed, xtype \\ "standard") do
    cap_i =
      :binary.bin_to_list(
        :crypto.hmac(
          :sha512,
          Exbtc.Core.from_string_to_bytes("Bitcoin seed"),
          seed
        )
      )

    {master_key, master_chain} = {Enum.slice(cap_i, 0..31), Enum.slice(cap_i, 32..-1)}

    compressed_pubkey = privkey_to_bin_compressed_pubkey(master_key)

    {
      serialize_xpriv(
        xpriv_header(xtype),
        master_chain,
        master_key
      ),
      serialize_xpub(
        xpub_header(xtype),
        master_chain,
        compressed_pubkey
      )
    }
  end

  @spec serialize_xpriv(
          list(byte),
          chaincode,
          binary_private_key,
          depth,
          fingerprint,
          child_number
        ) :: String.t()
  def serialize_xpriv(
        vbytes,
        chaincode,
        privkey,
        depth \\ 0,
        fingerprint \\ U.replicate(4, 0),
        child_number \\ U.replicate(4, 0)
      ) do
    (vbytes ++ [U.mod(depth, 256)] ++ fingerprint ++ child_number ++ chaincode ++ [0] ++ privkey)
    |> encode_base58()
  end

  @spec serialize_xpub(list(byte), chaincode, binary_public_key, depth, fingerprint, child_number) ::
          String.t()
  def serialize_xpub(
        vbytes,
        chaincode,
        pubkey,
        depth \\ 0,
        fingerprint \\ U.replicate(4, 0),
        child_number \\ U.replicate(4, 0)
      ) do
    (vbytes ++ [U.mod(depth, 256)] ++ fingerprint ++ child_number ++ chaincode ++ pubkey)
    |> encode_base58()
  end

  @spec deserialize_key(String.t(), boolean) ::
          {String.t(), chaincode, binary_private_key | binary_public_key, depth, fingerprint,
           child_number}
  defp deserialize_key(key, priv?) do
    xkey = decode_base58(key)
    if length(xkey) != 78, do: raise("Invalid key length")

    # {vbytes, chaincode, priv_pub_key, depth, fingerprint, child_number}
    case priv? do
      true ->
        {
          Enum.slice(xkey, 0..3) |> vbytes_xpriv_header(),
          Enum.slice(xkey, 13..44),
          # skip 1 byte after
          Enum.slice(xkey, 46..-1),
          Enum.at(xkey, 4),
          Enum.slice(xkey, 5..8),
          Enum.slice(xkey, 9..12)
        }

      _ ->
        {
          Enum.slice(xkey, 0..3) |> vbytes_xpub_header(),
          Enum.slice(xkey, 13..44),
          Enum.slice(xkey, 45..-1),
          Enum.at(xkey, 4),
          Enum.slice(xkey, 5..8),
          Enum.slice(xkey, 9..12)
        }
    end
  end

  def deserialize_xpub(key) do
    deserialize_key(key, false)
  end

  def deserialize_xpriv(key) do
    deserialize_key(key, true)
  end

  @spec encode_base58(list(byte)) :: String.t()
  def encode_base58(bin) do
    (bin ++ Enum.slice(Exbtc.Core.bin_double_sha256(bin), 0..3)) |> Exbtc.Core.changebase(256, 58)
  end

  def decode_base58(encoded_str) do
    {key, checksum} = Exbtc.Core.changebase(encoded_str, 58, 256) |> Enum.split(-4)

    if Enum.slice(Exbtc.Core.bin_double_sha256(key), 0..3) != checksum do
      raise "Checksum failed when decoding base58Check"
    else
      key
    end
  end

  @doc """
    Exbtc.Core.privkey_to_pubkey(key) returns a "bin"-format pubkey, we need "bin_compressed"-format pubkey
  """
  @spec privkey_to_bin_compressed_pubkey(binary_private_key) :: binary_public_key
  def privkey_to_bin_compressed_pubkey(key) do
    Exbtc.Core.privkey_to_pubkey(key) |> Exbtc.Core.decode_pubkey()
    |> Exbtc.Core.encode_pubkey("bin_compressed")
  end
end
