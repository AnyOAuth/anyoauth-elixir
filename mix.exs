defmodule AnyOAuth.MixProject do
  use Mix.Project
  def project, do: [app: :anyoauth_sdk, version: "0.1.0", elixir: ">= 1.14.0", deps: [{:jason, "~> 1.4"}], description: "AnyOAuth confidential backend SDK", package: [licenses: ["MIT"], files: ["lib", "mix.exs", "README.md", "LICENSE", "schema.json"]]]
  def application, do: [extra_applications: [:inets, :ssl, :crypto, :public_key]]
end
