# Berth allocation
defmodule Harbour.Berths do
  @moduledoc "Allocates berths."
  alias Harbour.Boat
  import Ecto.Query

  def allocate(%Boat{} = boat), do: {:ok, boat}

  defp free?(_berth), do: true
end
