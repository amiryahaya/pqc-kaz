defmodule KazSign.MixProject do
  use Mix.Project

  @version "2.0.0"
  @source_url "https://github.com/anthropic/pqc-kaz"

  def project do
    [
      app: :kaz_sign,
      version: @version,
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      compilers: [:elixir_make] ++ Mix.compilers(),
      make_targets: ["all"],
      make_clean: ["clean"],
      deps: deps(),
      package: package(),
      description: "Elixir NIF bindings for KAZ-SIGN post-quantum digital signatures",
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp deps do
    [
      {:elixir_make, "~> 0.8", runtime: false},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      name: "kaz_sign",
      files: ~w(lib c_src mix.exs README.md LICENSE Makefile),
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url}
    ]
  end

  defp docs do
    [
      main: "KazSign",
      source_url: @source_url,
      extras: ["README.md"]
    ]
  end
end
