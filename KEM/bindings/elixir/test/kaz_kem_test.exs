defmodule KazKemTest do
  use ExUnit.Case
  doctest KazKem

  setup do
    # Cleanup before each test
    KazKem.cleanup()
    :ok
  end

  describe "init/1" do
    test "initializes with level 128" do
      assert :ok = KazKem.init(128)
      assert KazKem.initialized?()
      assert {:ok, 128} = KazKem.get_level()
    end

    test "initializes with level 192" do
      assert :ok = KazKem.init(192)
      assert {:ok, 192} = KazKem.get_level()
    end

    test "initializes with level 256" do
      assert :ok = KazKem.init(256)
      assert {:ok, 256} = KazKem.get_level()
    end

    test "rejects invalid level" do
      assert {:error, :invalid_level} = KazKem.init(999)
      assert {:error, :invalid_level} = KazKem.init(64)
    end

    test "can reinitialize with different level" do
      assert :ok = KazKem.init(128)
      assert {:ok, 128} = KazKem.get_level()

      assert :ok = KazKem.init(256)
      assert {:ok, 256} = KazKem.get_level()
    end
  end

  describe "get_sizes/0" do
    test "returns correct sizes for level 128" do
      :ok = KazKem.init(128)
      {:ok, sizes} = KazKem.get_sizes()

      assert sizes.public_key == 108
      assert sizes.private_key == 34
      assert is_integer(sizes.ciphertext)
      assert is_integer(sizes.shared_secret)
    end

    test "returns correct sizes for level 192" do
      :ok = KazKem.init(192)
      {:ok, sizes} = KazKem.get_sizes()

      assert sizes.public_key == 176
      assert sizes.private_key == 50
    end

    test "returns correct sizes for level 256" do
      :ok = KazKem.init(256)
      {:ok, sizes} = KazKem.get_sizes()

      assert sizes.public_key == 236
      assert sizes.private_key == 66
    end

    test "returns error when not initialized" do
      assert {:error, :not_initialized} = KazKem.get_sizes()
    end
  end

  describe "keypair/0" do
    test "generates keypair for level 128" do
      :ok = KazKem.init(128)
      {:ok, keypair} = KazKem.keypair()

      assert is_binary(keypair.public_key)
      assert is_binary(keypair.private_key)
      assert byte_size(keypair.public_key) == 108
      assert byte_size(keypair.private_key) == 34
    end

    test "generates keypair for level 192" do
      :ok = KazKem.init(192)
      {:ok, keypair} = KazKem.keypair()

      assert byte_size(keypair.public_key) == 176
      assert byte_size(keypair.private_key) == 50
    end

    test "generates keypair for level 256" do
      :ok = KazKem.init(256)
      {:ok, keypair} = KazKem.keypair()

      assert byte_size(keypair.public_key) == 236
      assert byte_size(keypair.private_key) == 66
    end

    test "generates different keypairs each time" do
      :ok = KazKem.init(128)
      {:ok, keypair1} = KazKem.keypair()
      {:ok, keypair2} = KazKem.keypair()

      assert keypair1.public_key != keypair2.public_key
      assert keypair1.private_key != keypair2.private_key
    end

    test "returns error when not initialized" do
      assert {:error, :not_initialized} = KazKem.keypair()
    end
  end

  describe "encapsulate/2 and decapsulate/3" do
    # Note: KAZ-KEM automatically pads secrets to the full shared_secret size
    # and returns the full size on decapsulation. Use decapsulate/3 to trim.

    test "round-trip works for level 128" do
      :ok = KazKem.init(128)
      {:ok, keypair} = KazKem.keypair()

      # Use 16 bytes - will be left-padded to 54 bytes internally
      shared_secret = :crypto.strong_rand_bytes(16)
      secret_len = byte_size(shared_secret)

      # Encapsulate
      {:ok, ciphertext} = KazKem.encapsulate(shared_secret, keypair.public_key)
      assert is_binary(ciphertext)

      # Decapsulate with original length to trim
      {:ok, recovered} = KazKem.decapsulate(ciphertext, keypair.private_key, secret_len)
      assert recovered == shared_secret
    end

    test "round-trip works for level 192" do
      :ok = KazKem.init(192)
      {:ok, keypair} = KazKem.keypair()

      # Use 24 bytes
      shared_secret = :crypto.strong_rand_bytes(24)
      secret_len = byte_size(shared_secret)
      {:ok, ciphertext} = KazKem.encapsulate(shared_secret, keypair.public_key)
      {:ok, recovered} = KazKem.decapsulate(ciphertext, keypair.private_key, secret_len)

      assert recovered == shared_secret
    end

    test "round-trip works for level 256" do
      :ok = KazKem.init(256)
      {:ok, keypair} = KazKem.keypair()

      # Use 32 bytes
      shared_secret = :crypto.strong_rand_bytes(32)
      secret_len = byte_size(shared_secret)
      {:ok, ciphertext} = KazKem.encapsulate(shared_secret, keypair.public_key)
      {:ok, recovered} = KazKem.decapsulate(ciphertext, keypair.private_key, secret_len)

      assert recovered == shared_secret
    end

    test "round-trip works with full size secrets" do
      :ok = KazKem.init(128)
      {:ok, keypair} = KazKem.keypair()
      {:ok, sizes} = KazKem.get_sizes()

      # Use full shared_secret size (54 bytes for level 128)
      shared_secret = :crypto.strong_rand_bytes(sizes.shared_secret)
      {:ok, ciphertext} = KazKem.encapsulate(shared_secret, keypair.public_key)
      {:ok, recovered} = KazKem.decapsulate(ciphertext, keypair.private_key)

      # Without trimming, should match exactly
      assert recovered == shared_secret
    end

    test "decapsulate fails with wrong private key" do
      :ok = KazKem.init(128)
      {:ok, keypair1} = KazKem.keypair()
      {:ok, keypair2} = KazKem.keypair()

      shared_secret = :crypto.strong_rand_bytes(16)
      {:ok, ciphertext} = KazKem.encapsulate(shared_secret, keypair1.public_key)

      # Try to decapsulate with wrong key - should return wrong result
      {:ok, recovered} = KazKem.decapsulate(ciphertext, keypair2.private_key, 16)
      assert recovered != shared_secret
    end
  end

  describe "version/0" do
    test "returns version string" do
      version = KazKem.version()
      assert is_binary(version)
      assert String.match?(version, ~r/^\d+\.\d+\.\d+/)
    end
  end

  describe "cleanup/0" do
    test "cleanup succeeds" do
      :ok = KazKem.init(128)
      assert :ok = KazKem.cleanup()
    end

    test "cleanup is idempotent" do
      :ok = KazKem.init(128)
      assert :ok = KazKem.cleanup()
      assert :ok = KazKem.cleanup()
    end
  end
end
