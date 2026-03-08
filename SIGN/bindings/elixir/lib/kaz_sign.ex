defmodule KazSign do
  @moduledoc """
  KAZ-SIGN - Post-Quantum Digital Signature Scheme.

  KAZ-SIGN is a post-quantum secure digital signature scheme based on
  the discrete logarithm problem in finite groups with unknown order.

  ## Security Levels

  - `128` - 128-bit security (SHA-256 based)
  - `192` - 192-bit security (SHA-384 based)
  - `256` - 256-bit security (SHA-512 based)

  ## Signature Format

  KAZ-SIGN uses a message-recovery signature scheme. The signature
  includes the original message, and verification recovers the message.

  ## Usage

      # Initialize (required once)
      :ok = KazSign.init()

      # Generate keypair for level 128
      {:ok, keypair} = KazSign.keypair(128)

      # Sign a message
      {:ok, signature} = KazSign.sign(128, "Hello, World!", keypair.private_key)

      # Verify and recover message
      {:ok, message} = KazSign.verify(128, signature, keypair.public_key)

      # Cleanup when done
      :ok = KazSign.cleanup()

  ## Thread Safety

  The NIF bindings use a mutex to ensure thread-safe access to the
  underlying C library.
  """

  alias KazSign.Nif

  @type level :: 128 | 192 | 256
  @type keypair :: %{public_key: binary(), private_key: binary()}
  @type sizes :: %{
          public_key: non_neg_integer(),
          private_key: non_neg_integer(),
          hash: non_neg_integer(),
          signature_overhead: non_neg_integer()
        }

  @doc """
  Initialize KAZ-SIGN random number generator.

  Must be called before any other KAZ-SIGN operations.

  ## Returns

  - `:ok` on success
  - `{:error, reason}` on failure
  """
  @spec init() :: :ok | {:error, atom()}
  def init do
    Nif.nif_init()
  end

  @doc """
  Initialize KAZ-SIGN for a specific security level.

  Also initializes the RNG if not already initialized.

  ## Parameters

  - `level` - Security level: 128, 192, or 256

  ## Returns

  - `:ok` on success
  - `{:error, reason}` on failure
  """
  @spec init(level()) :: :ok | {:error, atom()}
  def init(level) when level in [128, 192, 256] do
    Nif.nif_init_level(level)
  end

  def init(_level), do: {:error, :invalid_level}

  @doc """
  Check if KAZ-SIGN has been initialized.

  ## Returns

  - `true` if initialized
  - `false` if not initialized
  """
  @spec initialized?() :: boolean()
  def initialized? do
    Nif.nif_is_initialized() == true
  end

  @doc """
  Get the sizes of keys and signatures for a specific security level.

  ## Parameters

  - `level` - Security level: 128, 192, or 256

  ## Returns

  - `{:ok, sizes}` with a map containing:
    - `:public_key` - public key size in bytes
    - `:private_key` - private key size in bytes
    - `:hash` - hash output size in bytes
    - `:signature_overhead` - signature overhead in bytes (actual signature = overhead + message length)
  - `{:error, reason}` on failure
  """
  @spec get_sizes(level()) :: {:ok, sizes()} | {:error, atom()}
  def get_sizes(level) when level in [128, 192, 256] do
    Nif.nif_get_sizes(level)
  end

  def get_sizes(_level), do: {:error, :invalid_level}

  @doc """
  Generate a new signing keypair.

  ## Parameters

  - `level` - Security level: 128, 192, or 256

  ## Returns

  - `{:ok, keypair}` with a map containing:
    - `:public_key` - the public key binary
    - `:private_key` - the private key binary
  - `{:error, reason}` on failure

  ## Examples

      iex> KazSign.init()
      :ok
      iex> {:ok, keypair} = KazSign.keypair(128)
      iex> is_binary(keypair.public_key)
      true
  """
  @spec keypair(level()) :: {:ok, keypair()} | {:error, atom()}
  def keypair(level) when level in [128, 192, 256] do
    Nif.nif_keypair(level)
  end

  def keypair(_level), do: {:error, :invalid_level}

  @doc """
  Sign a message.

  The signature includes the message (message-recovery scheme).

  ## Parameters

  - `level` - Security level: 128, 192, or 256
  - `message` - The message to sign (binary or string)
  - `private_key` - The private key

  ## Returns

  - `{:ok, signature}` - The signature containing the message
  - `{:error, reason}` on failure

  ## Examples

      iex> {:ok, keypair} = KazSign.keypair(128)
      iex> {:ok, signature} = KazSign.sign(128, "Hello!", keypair.private_key)
      iex> is_binary(signature)
      true
  """
  @spec sign(level(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def sign(level, message, private_key)
      when level in [128, 192, 256] and is_binary(message) and is_binary(private_key) do
    Nif.nif_sign(level, message, private_key)
  end

  def sign(_level, _message, _private_key), do: {:error, :invalid_argument}

  @doc """
  Verify a signature and recover the original message.

  ## Parameters

  - `level` - Security level: 128, 192, or 256
  - `signature` - The signature to verify
  - `public_key` - The public key

  ## Returns

  - `{:ok, message}` - The recovered original message
  - `{:error, :invalid_signature}` - If verification fails
  - `{:error, reason}` - On other errors

  ## Examples

      iex> {:ok, keypair} = KazSign.keypair(128)
      iex> {:ok, signature} = KazSign.sign(128, "Hello!", keypair.private_key)
      iex> {:ok, message} = KazSign.verify(128, signature, keypair.public_key)
      iex> message
      "Hello!"
  """
  @spec verify(level(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def verify(level, signature, public_key)
      when level in [128, 192, 256] and is_binary(signature) and is_binary(public_key) do
    Nif.nif_verify(level, signature, public_key)
  end

  def verify(_level, _signature, _public_key), do: {:error, :invalid_argument}

  @doc """
  Verify a signature without recovering the message.

  Returns `true` if the signature is valid, `false` otherwise.

  ## Parameters

  - `level` - Security level: 128, 192, or 256
  - `signature` - The signature to verify
  - `public_key` - The public key

  ## Returns

  - `true` if signature is valid
  - `false` if signature is invalid
  """
  @spec valid?(level(), binary(), binary()) :: boolean()
  def valid?(level, signature, public_key) do
    case verify(level, signature, public_key) do
      {:ok, _message} -> true
      {:error, _} -> false
    end
  end

  @doc """
  Hash a message using the level-specific hash function.

  - Level 128: SHA-256 (32 bytes)
  - Level 192: SHA-384 (48 bytes)
  - Level 256: SHA-512 (64 bytes)

  ## Parameters

  - `level` - Security level: 128, 192, or 256
  - `message` - The message to hash

  ## Returns

  - `{:ok, hash}` - The hash digest
  - `{:error, reason}` on failure
  """
  @spec hash(level(), binary()) :: {:ok, binary()} | {:error, atom()}
  def hash(level, message) when level in [128, 192, 256] and is_binary(message) do
    Nif.nif_hash(level, message)
  end

  def hash(_level, _message), do: {:error, :invalid_argument}

  @doc """
  Create a detached signature (signature does not include the message).

  ## Parameters

  - `level` - Security level: 128, 192, or 256
  - `data` - The data to sign (binary or string)
  - `secret_key` - The secret signing key

  ## Returns

  - `{:ok, signature}` - The detached signature
  - `{:error, reason}` on failure

  ## Examples

      iex> {:ok, keypair} = KazSign.keypair(128)
      iex> {:ok, sig} = KazSign.sign_detached(128, "Hello!", keypair.private_key)
      iex> is_binary(sig)
      true
  """
  @spec sign_detached(level(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def sign_detached(level, data, secret_key)
      when level in [128, 192, 256] and is_binary(data) and is_binary(secret_key) do
    Nif.nif_sign_detached(level, data, secret_key)
  end

  def sign_detached(_level, _data, _secret_key), do: {:error, :invalid_argument}

  @doc """
  Verify a detached signature.

  ## Parameters

  - `level` - Security level: 128, 192, or 256
  - `data` - The original data that was signed
  - `signature` - The detached signature to verify
  - `public_key` - The public verification key

  ## Returns

  - `{:ok, true}` if signature is valid
  - `{:ok, false}` if signature is invalid
  - `{:error, reason}` on other errors

  ## Examples

      iex> {:ok, keypair} = KazSign.keypair(128)
      iex> {:ok, sig} = KazSign.sign_detached(128, "Hello!", keypair.private_key)
      iex> KazSign.verify_detached(128, "Hello!", sig, keypair.public_key)
      {:ok, true}
  """
  @spec verify_detached(level(), binary(), binary(), binary()) :: {:ok, boolean()} | {:error, atom()}
  def verify_detached(level, data, signature, public_key)
      when level in [128, 192, 256] and is_binary(data) and is_binary(signature) and is_binary(public_key) do
    Nif.nif_verify_detached(level, data, signature, public_key)
  end

  def verify_detached(_level, _data, _signature, _public_key), do: {:error, :invalid_argument}

  @doc """
  Compute SHA3-256 hash of data.

  ## Parameters

  - `data` - The data to hash

  ## Returns

  - `{:ok, hash}` - 32-byte SHA3-256 digest
  - `{:error, reason}` on failure

  ## Examples

      iex> {:ok, hash} = KazSign.sha3_256("Hello!")
      iex> byte_size(hash)
      32
  """
  @spec sha3_256(binary()) :: {:ok, binary()} | {:error, atom()}
  def sha3_256(data) when is_binary(data) do
    Nif.nif_sha3_256(data)
  end

  def sha3_256(_data), do: {:error, :invalid_argument}

  @doc """
  Encode a public key to DER format.

  ## Parameters

  - `level` - Security level: 128, 192, or 256
  - `public_key` - The raw public key binary

  ## Returns

  - `{:ok, der}` - DER-encoded public key
  - `{:error, reason}` on failure
  """
  @spec pubkey_to_der(level(), binary()) :: {:ok, binary()} | {:error, atom()}
  def pubkey_to_der(level, public_key)
      when level in [128, 192, 256] and is_binary(public_key) do
    Nif.nif_pubkey_to_der(level, public_key)
  end

  def pubkey_to_der(_level, _public_key), do: {:error, :invalid_argument}

  @doc """
  Decode a public key from DER format.

  ## Parameters

  - `level` - Security level: 128, 192, or 256
  - `der` - DER-encoded public key

  ## Returns

  - `{:ok, public_key}` - The raw public key binary
  - `{:error, reason}` on failure
  """
  @spec pubkey_from_der(level(), binary()) :: {:ok, binary()} | {:error, atom()}
  def pubkey_from_der(level, der)
      when level in [128, 192, 256] and is_binary(der) do
    Nif.nif_pubkey_from_der(level, der)
  end

  def pubkey_from_der(_level, _der), do: {:error, :invalid_argument}

  @doc """
  Encode a private key to DER format.

  ## Parameters

  - `level` - Security level: 128, 192, or 256
  - `secret_key` - The raw secret key binary

  ## Returns

  - `{:ok, der}` - DER-encoded private key
  - `{:error, reason}` on failure
  """
  @spec privkey_to_der(level(), binary()) :: {:ok, binary()} | {:error, atom()}
  def privkey_to_der(level, secret_key)
      when level in [128, 192, 256] and is_binary(secret_key) do
    Nif.nif_privkey_to_der(level, secret_key)
  end

  def privkey_to_der(_level, _secret_key), do: {:error, :invalid_argument}

  @doc """
  Decode a private key from DER format.

  ## Parameters

  - `level` - Security level: 128, 192, or 256
  - `der` - DER-encoded private key

  ## Returns

  - `{:ok, secret_key}` - The raw secret key binary
  - `{:error, reason}` on failure
  """
  @spec privkey_from_der(level(), binary()) :: {:ok, binary()} | {:error, atom()}
  def privkey_from_der(level, der)
      when level in [128, 192, 256] and is_binary(der) do
    Nif.nif_privkey_from_der(level, der)
  end

  def privkey_from_der(_level, _der), do: {:error, :invalid_argument}

  @doc """
  Generate a PKCS#10 Certificate Signing Request (CSR).

  ## Parameters

  - `level` - Security level: 128, 192, or 256
  - `secret_key` - The secret signing key
  - `public_key` - The public key
  - `subject` - Subject distinguished name (e.g., "CN=test")

  ## Returns

  - `{:ok, csr}` - DER-encoded CSR
  - `{:error, reason}` on failure

  ## Examples

      iex> {:ok, keypair} = KazSign.keypair(128)
      iex> {:ok, csr} = KazSign.generate_csr(128, keypair.private_key, keypair.public_key, "CN=test")
      iex> is_binary(csr)
      true
  """
  @spec generate_csr(level(), binary(), binary(), String.t()) :: {:ok, binary()} | {:error, atom()}
  def generate_csr(level, secret_key, public_key, subject)
      when level in [128, 192, 256] and is_binary(secret_key) and is_binary(public_key) do
    Nif.nif_generate_csr(level, secret_key, public_key, to_charlist(subject))
  end

  def generate_csr(_level, _secret_key, _public_key, _subject), do: {:error, :invalid_argument}

  @doc """
  Verify a PKCS#10 CSR self-signature.

  ## Parameters

  - `level` - Security level: 128, 192, or 256
  - `csr` - DER-encoded CSR

  ## Returns

  - `{:ok, true}` if CSR signature is valid
  - `{:ok, false}` if CSR signature is invalid
  - `{:error, reason}` on other errors
  """
  @spec verify_csr(level(), binary()) :: {:ok, boolean()} | {:error, atom()}
  def verify_csr(level, csr)
      when level in [128, 192, 256] and is_binary(csr) do
    Nif.nif_verify_csr(level, csr)
  end

  def verify_csr(_level, _csr), do: {:error, :invalid_argument}

  @doc """
  Issue an X.509 certificate by signing a CSR.

  ## Parameters

  - `level` - Security level: 128, 192, or 256
  - `issuer_sk` - Issuer's secret signing key
  - `issuer_pk` - Issuer's public key
  - `csr` - DER-encoded CSR from the subject
  - `opts` - Options keyword list:
    - `:issuer_name` - Issuer distinguished name (e.g., "CN=CA") (required)
    - `:serial` - Certificate serial number (required)
    - `:days` - Validity period in days (required)

  ## Returns

  - `{:ok, cert}` - DER-encoded X.509 certificate
  - `{:error, reason}` on failure

  ## Examples

      iex> {:ok, ca} = KazSign.keypair(128)
      iex> {:ok, subj} = KazSign.keypair(128)
      iex> {:ok, csr} = KazSign.generate_csr(128, subj.private_key, subj.public_key, "CN=subject")
      iex> {:ok, cert} = KazSign.issue_certificate(128, ca.private_key, ca.public_key, csr,
      ...>   issuer_name: "CN=CA", serial: 1, days: 365)
      iex> is_binary(cert)
      true
  """
  @spec issue_certificate(level(), binary(), binary(), binary(), keyword()) ::
          {:ok, binary()} | {:error, atom()}
  def issue_certificate(level, issuer_sk, issuer_pk, csr, opts)
      when level in [128, 192, 256] and is_binary(issuer_sk) and is_binary(issuer_pk) and is_binary(csr) and is_list(opts) do
    issuer_name = Keyword.fetch!(opts, :issuer_name)
    serial = Keyword.fetch!(opts, :serial)
    days = Keyword.fetch!(opts, :days)

    Nif.nif_issue_certificate(level, issuer_sk, issuer_pk,
                               to_charlist(issuer_name), csr, serial, days)
  end

  def issue_certificate(_level, _issuer_sk, _issuer_pk, _csr, _opts),
    do: {:error, :invalid_argument}

  @doc """
  Verify an X.509 certificate signature against an issuer public key.

  ## Parameters

  - `level` - Security level: 128, 192, or 256
  - `cert` - DER-encoded X.509 certificate
  - `issuer_pk` - Issuer's public key

  ## Returns

  - `{:ok, true}` if certificate signature is valid
  - `{:ok, false}` if certificate signature is invalid
  - `{:error, reason}` on other errors
  """
  @spec verify_certificate(level(), binary(), binary()) :: {:ok, boolean()} | {:error, atom()}
  def verify_certificate(level, cert, issuer_pk)
      when level in [128, 192, 256] and is_binary(cert) and is_binary(issuer_pk) do
    Nif.nif_verify_certificate(level, cert, issuer_pk)
  end

  def verify_certificate(_level, _cert, _issuer_pk), do: {:error, :invalid_argument}

  @doc """
  Extract the public key from an X.509 certificate.

  ## Parameters

  - `level` - Security level: 128, 192, or 256
  - `cert` - DER-encoded X.509 certificate

  ## Returns

  - `{:ok, public_key}` - The extracted public key
  - `{:error, reason}` on failure
  """
  @spec extract_pubkey(level(), binary()) :: {:ok, binary()} | {:error, atom()}
  def extract_pubkey(level, cert)
      when level in [128, 192, 256] and is_binary(cert) do
    Nif.nif_cert_extract_pubkey(level, cert)
  end

  def extract_pubkey(_level, _cert), do: {:error, :invalid_argument}

  @doc """
  Create a PKCS#12 keystore containing a key pair and optional certificate.

  ## Parameters

  - `level` - Security level: 128, 192, or 256
  - `secret_key` - The secret signing key
  - `cert` - DER-encoded certificate (use `<<>>` for no certificate)
  - `chain` - Certificate chain (currently unused, pass `[]`)
  - `password` - Password to protect the keystore
  - `name` - Friendly name for the key entry

  ## Returns

  - `{:ok, p12}` - PKCS#12 keystore data
  - `{:error, reason}` on failure

  ## Note

  The public key is extracted from the certificate. If no certificate is
  provided, use `create_p12/7` which accepts the public key explicitly.
  """
  @spec create_p12(level(), binary(), binary(), list(), String.t(), String.t()) ::
          {:ok, binary()} | {:error, atom()}
  def create_p12(level, secret_key, cert, chain, password, name)
      when level in [128, 192, 256] and is_binary(secret_key) and is_binary(cert) and is_list(chain) do
    # Extract public key from certificate for the C API
    case extract_pubkey(level, cert) do
      {:ok, public_key} ->
        Nif.nif_create_p12(level, secret_key, public_key, cert,
                            to_charlist(password), to_charlist(name))

      {:error, _reason} ->
        {:error, :invalid_argument}
    end
  end

  def create_p12(_level, _secret_key, _cert, _chain, _password, _name),
    do: {:error, :invalid_argument}

  @doc """
  Load a key pair and certificate from a PKCS#12 keystore.

  ## Parameters

  - `level` - Security level: 128, 192, or 256
  - `p12` - PKCS#12 keystore data
  - `password` - Password to unlock the keystore

  ## Returns

  - `{:ok, %{private_key: binary, public_key: binary, cert: binary}}` on success
  - `{:error, reason}` on failure
  """
  @spec load_p12(level(), binary(), String.t()) ::
          {:ok, %{private_key: binary(), public_key: binary(), cert: binary()}} | {:error, atom()}
  def load_p12(level, p12, password)
      when level in [128, 192, 256] and is_binary(p12) do
    Nif.nif_load_p12(level, p12, to_charlist(password))
  end

  def load_p12(_level, _p12, _password), do: {:error, :invalid_argument}

  @doc """
  Cleanup KAZ-SIGN state and free resources.

  Should be called when KAZ-SIGN is no longer needed.

  ## Returns

  - `:ok`
  """
  @spec cleanup() :: :ok
  def cleanup do
    Nif.nif_cleanup()
  end

  @doc """
  Get the KAZ-SIGN library version.

  ## Returns

  Version string (e.g., "2.1.0")
  """
  @spec version() :: String.t()
  def version do
    Nif.nif_version() |> to_string()
  end
end
