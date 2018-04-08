defmodule Curium.Mnemonic do
  @type seed :: bitstring()
  @type mnemonic :: String.t()

  alias Curium.U

  @english_word_list File.read!(Path.expand("../english.txt", __DIR__))
                     |> String.split("\n")

  def english_word_list, do: @english_word_list

  @doc """
    returns 64 bytes binary
    TODO  replace "electrum" prefix later on
  """
  @spec mnemonic_to_seed(mnemonic, String.t()) :: {:ok, seed}
  def mnemonic_to_seed(mnemonic, passphrase) do
    :pbkdf2.pbkdf2(:sha512, mnemonic, "electrum" <> passphrase, _iterations = 2048)
  end

  @doc """
    encode an integer to english words list
  """
  @spec encode(integer) :: mnemonic
  def encode(n) do
    len = length(@english_word_list)
    _encode(n, len, []) |> Enum.join(" ")
  end

  defp _encode(0, _, acc), do: acc

  defp _encode(num, max, acc) do
    i = rem(num, max)
    re = div(num, max)
    _encode(re, max, acc ++ [Enum.at(@english_word_list, i)])
  end

  @doc """
    decode a string (word list) into a number
  """
  @spec decode(mnemonic) :: integer
  def decode(seed) do
    len = length(@english_word_list)

    String.split(seed, " ")
    |> Enum.reverse()
    |> Enum.reduce(0, fn word, sum ->
      i = Enum.find_index(@english_word_list, fn w -> w == word end)
      sum * len + i
    end)
  end

  @doc """
    default number of bits for the seed is 132 bits.
  """
  @spec gen_seed(integer) :: mnemonic
  def gen_seed(nr_bits \\ 132) do
    pw = :math.log2(length(@english_word_list))
    adjusted_bits = max(round(Float.ceil(nr_bits / pw) * pw), 16)
    entropy = gen_entropy(1, round(adjusted_bits - pw))
    seed = encode(entropy + 1)
    if entropy + 1 != decode(seed), do: raise("Error creating seed")
    seed
  end

  defp gen_entropy(i, pow) do
    if i < U.power(2, pow) + 1 do
      x =
        round(Float.ceil(pow / 8))
        |> :crypto.strong_rand_bytes()
        |> :crypto.bytes_to_integer()

      gen_entropy(x, pow)
    else
      i
    end
  end
end
