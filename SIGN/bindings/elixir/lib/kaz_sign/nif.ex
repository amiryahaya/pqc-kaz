defmodule KazSign.Nif do
  @moduledoc false

  @on_load :load_nif

  @doc false
  def load_nif do
    path = :filename.join(:code.priv_dir(:kaz_sign), ~c"kaz_sign_nif")

    case :erlang.load_nif(path, 0) do
      :ok -> :ok
      {:error, {:reload, _}} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc false
  def nif_init do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_init_level(_level) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_is_initialized do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_get_sizes(_level) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_keypair(_level) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_sign(_level, _message, _private_key) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_verify(_level, _signature, _public_key) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_hash(_level, _message) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_sign_detached(_level, _message, _private_key) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_verify_detached(_level, _message, _signature, _public_key) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_sha3_256(_data) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_pubkey_to_der(_level, _public_key) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_pubkey_from_der(_level, _der) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_privkey_to_der(_level, _private_key) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_privkey_from_der(_level, _der) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_generate_csr(_level, _private_key, _public_key, _subject) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_verify_csr(_level, _csr) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_issue_certificate(_level, _issuer_sk, _issuer_pk, _issuer_name, _csr, _serial, _days) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_verify_certificate(_level, _cert, _issuer_pk) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_cert_extract_pubkey(_level, _cert) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_create_p12(_level, _private_key, _public_key, _cert, _password, _name) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_load_p12(_level, _p12, _password) do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_cleanup do
    :erlang.nif_error(:nif_not_loaded)
  end

  @doc false
  def nif_version do
    :erlang.nif_error(:nif_not_loaded)
  end
end
