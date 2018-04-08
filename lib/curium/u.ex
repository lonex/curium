defmodule Curium.U do
  import Extension
  extends(Exbtc.U)

  @doc """
    the term `bytes` is used as `charlist` in naming the method and argument here
  """
  def from_string_to_bytes(s) do
    String.to_charlist(s)
  end

  @spec bytes_to_hex_string(binary) :: String.t()
  def bytes_to_hex_string(bin) do
    Base.encode16(bin, case: :lower)
  end
end
