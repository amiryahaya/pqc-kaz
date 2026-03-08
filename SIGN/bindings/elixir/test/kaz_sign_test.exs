defmodule KazSignTest do
  use ExUnit.Case
  doctest KazSign

  setup do
    # Cleanup before each test
    KazSign.cleanup()
    :ok
  end

  describe "init/0" do
    test "initializes successfully" do
      assert :ok = KazSign.init()
      assert KazSign.initialized?()
    end
  end

  describe "init/1" do
    test "initializes with level 128" do
      assert :ok = KazSign.init(128)
      assert KazSign.initialized?()
    end

    test "initializes with level 192" do
      assert :ok = KazSign.init(192)
      assert KazSign.initialized?()
    end

    test "initializes with level 256" do
      assert :ok = KazSign.init(256)
      assert KazSign.initialized?()
    end

    test "rejects invalid level" do
      assert {:error, :invalid_level} = KazSign.init(999)
    end
  end

  describe "get_sizes/1" do
    test "returns correct sizes for level 128" do
      {:ok, sizes} = KazSign.get_sizes(128)

      assert sizes.public_key == 54
      assert sizes.private_key == 32
      assert sizes.hash == 32
      assert sizes.signature_overhead == 162
    end

    test "returns correct sizes for level 192" do
      {:ok, sizes} = KazSign.get_sizes(192)

      assert sizes.public_key == 88
      assert sizes.private_key == 50
      assert sizes.hash == 48
      assert sizes.signature_overhead == 264
    end

    test "returns correct sizes for level 256" do
      {:ok, sizes} = KazSign.get_sizes(256)

      assert sizes.public_key == 118
      assert sizes.private_key == 64
      assert sizes.hash == 64
      assert sizes.signature_overhead == 356
    end
  end

  describe "keypair/1" do
    test "generates keypair for level 128" do
      :ok = KazSign.init()
      {:ok, keypair} = KazSign.keypair(128)

      assert is_binary(keypair.public_key)
      assert is_binary(keypair.private_key)
      assert byte_size(keypair.public_key) == 54
      assert byte_size(keypair.private_key) == 32
    end

    test "generates keypair for level 192" do
      :ok = KazSign.init()
      {:ok, keypair} = KazSign.keypair(192)

      assert byte_size(keypair.public_key) == 88
      assert byte_size(keypair.private_key) == 50
    end

    test "generates keypair for level 256" do
      :ok = KazSign.init()
      {:ok, keypair} = KazSign.keypair(256)

      assert byte_size(keypair.public_key) == 118
      assert byte_size(keypair.private_key) == 64
    end

    test "generates different keypairs each time" do
      :ok = KazSign.init()
      {:ok, keypair1} = KazSign.keypair(128)
      {:ok, keypair2} = KazSign.keypair(128)

      assert keypair1.public_key != keypair2.public_key
      assert keypair1.private_key != keypair2.private_key
    end
  end

  describe "sign/3 and verify/3" do
    test "round-trip works for level 128" do
      :ok = KazSign.init()
      {:ok, keypair} = KazSign.keypair(128)

      message = "Hello, World!"
      {:ok, signature} = KazSign.sign(128, message, keypair.private_key)

      assert is_binary(signature)
      assert byte_size(signature) == 162 + byte_size(message)

      {:ok, recovered} = KazSign.verify(128, signature, keypair.public_key)
      assert recovered == message
    end

    test "round-trip works for level 192" do
      :ok = KazSign.init()
      {:ok, keypair} = KazSign.keypair(192)

      message = "Test message for 192-bit security"
      {:ok, signature} = KazSign.sign(192, message, keypair.private_key)
      {:ok, recovered} = KazSign.verify(192, signature, keypair.public_key)

      assert recovered == message
    end

    test "round-trip works for level 256" do
      :ok = KazSign.init()
      {:ok, keypair} = KazSign.keypair(256)

      message = "High security message"
      {:ok, signature} = KazSign.sign(256, message, keypair.private_key)
      {:ok, recovered} = KazSign.verify(256, signature, keypair.public_key)

      assert recovered == message
    end

    test "works with binary data" do
      :ok = KazSign.init()
      {:ok, keypair} = KazSign.keypair(128)

      message = :crypto.strong_rand_bytes(100)
      {:ok, signature} = KazSign.sign(128, message, keypair.private_key)
      {:ok, recovered} = KazSign.verify(128, signature, keypair.public_key)

      assert recovered == message
    end

    test "verify fails with wrong public key" do
      :ok = KazSign.init()
      {:ok, keypair1} = KazSign.keypair(128)
      {:ok, keypair2} = KazSign.keypair(128)

      message = "Secret message"
      {:ok, signature} = KazSign.sign(128, message, keypair1.private_key)

      assert {:error, :invalid_signature} = KazSign.verify(128, signature, keypair2.public_key)
    end

    test "verify fails with tampered signature" do
      :ok = KazSign.init()
      {:ok, keypair} = KazSign.keypair(128)

      message = "Original message"
      {:ok, signature} = KazSign.sign(128, message, keypair.private_key)

      # Tamper with the signature
      <<first_byte, rest::binary>> = signature
      tampered = <<Bitwise.bxor(first_byte, 0xFF), rest::binary>>

      assert {:error, :invalid_signature} = KazSign.verify(128, tampered, keypair.public_key)
    end
  end

  describe "valid?/3" do
    test "returns true for valid signature" do
      :ok = KazSign.init()
      {:ok, keypair} = KazSign.keypair(128)

      message = "Test"
      {:ok, signature} = KazSign.sign(128, message, keypair.private_key)

      assert KazSign.valid?(128, signature, keypair.public_key)
    end

    test "returns false for invalid signature" do
      :ok = KazSign.init()
      {:ok, keypair} = KazSign.keypair(128)

      fake_signature = :crypto.strong_rand_bytes(200)

      refute KazSign.valid?(128, fake_signature, keypair.public_key)
    end
  end

  describe "hash/2" do
    test "returns 32-byte hash for level 128" do
      {:ok, hash} = KazSign.hash(128, "test message")
      assert byte_size(hash) == 32
    end

    test "returns 48-byte hash for level 192" do
      {:ok, hash} = KazSign.hash(192, "test message")
      assert byte_size(hash) == 48
    end

    test "returns 64-byte hash for level 256" do
      {:ok, hash} = KazSign.hash(256, "test message")
      assert byte_size(hash) == 64
    end

    test "same input produces same hash" do
      {:ok, hash1} = KazSign.hash(128, "test")
      {:ok, hash2} = KazSign.hash(128, "test")
      assert hash1 == hash2
    end

    test "different inputs produce different hashes" do
      {:ok, hash1} = KazSign.hash(128, "test1")
      {:ok, hash2} = KazSign.hash(128, "test2")
      assert hash1 != hash2
    end
  end

  describe "version/0" do
    test "returns version string" do
      version = KazSign.version()
      assert is_binary(version)
      assert String.match?(version, ~r/^\d+\.\d+\.\d+/)
    end
  end

  describe "cleanup/0" do
    test "cleanup succeeds" do
      :ok = KazSign.init()
      assert :ok = KazSign.cleanup()
    end

    test "cleanup is idempotent" do
      :ok = KazSign.init()
      assert :ok = KazSign.cleanup()
      assert :ok = KazSign.cleanup()
    end
  end
end
