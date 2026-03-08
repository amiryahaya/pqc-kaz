/*
 * KAZ-SIGN C# Example
 *
 * Demonstrates key generation, signing, and verification
 * for all three security levels (128, 192, 256).
 */

using System;
using System.Text;
using Antrapol.Kaz.Sign;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("==============================================");
        Console.WriteLine("KAZ-SIGN C# Wrapper Example");
        Console.WriteLine("==============================================\n");

        // Test all security levels
        TestSecurityLevel(SecurityLevel.Level128);
        TestSecurityLevel(SecurityLevel.Level192);
        TestSecurityLevel(SecurityLevel.Level256);

        Console.WriteLine("\nAll tests completed successfully!");
    }

    static void TestSecurityLevel(SecurityLevel level)
    {
        Console.WriteLine($"--- Security Level {(int)level} ---\n");

        using var signer = new KazSigner(level);

        // Display version info
        Console.WriteLine($"Library Version: {signer.GetVersion()}");
        Console.WriteLine($"Version Number:  {signer.GetVersionNumber()}\n");

        // Display key sizes
        Console.WriteLine($"Secret Key Size:     {signer.SecretKeyBytes} bytes");
        Console.WriteLine($"Public Key Size:     {signer.PublicKeyBytes} bytes");
        Console.WriteLine($"Signature Overhead:  {signer.SignatureOverhead} bytes");
        Console.WriteLine($"Hash Size:           {signer.HashBytes} bytes\n");

        // Generate key pair
        Console.Write("Generating key pair... ");
        signer.GenerateKeyPair(out byte[] publicKey, out byte[] secretKey);
        Console.WriteLine("OK");
        Console.WriteLine($"  Public Key:  {ToHex(publicKey, 16)}...");
        Console.WriteLine($"  Secret Key:  {ToHex(secretKey, 16)}...\n");

        // Sign a message
        string messageText = "Hello, Post-Quantum World!";
        byte[] message = Encoding.UTF8.GetBytes(messageText);

        Console.Write($"Signing message \"{messageText}\"... ");
        byte[] signature = signer.Sign(message, secretKey);
        Console.WriteLine("OK");
        Console.WriteLine($"  Signature:   {ToHex(signature, 16)}...");
        Console.WriteLine($"  Total Size:  {signature.Length} bytes (overhead + {message.Length} message)\n");

        // Verify the signature
        Console.Write("Verifying signature... ");
        bool isValid = signer.Verify(signature, publicKey, out byte[] recoveredMessage);
        Console.WriteLine(isValid ? "VALID" : "INVALID");

        if (isValid)
        {
            string recoveredText = Encoding.UTF8.GetString(recoveredMessage);
            Console.WriteLine($"  Recovered:   \"{recoveredText}\"\n");
        }

        // Test with invalid signature
        Console.Write("Testing tampered signature... ");
        byte[] tamperedSignature = (byte[])signature.Clone();
        tamperedSignature[0] ^= 0xFF;  // Flip bits in first byte
        bool tamperedValid = signer.Verify(tamperedSignature, publicKey, out _);
        Console.WriteLine(tamperedValid ? "ERROR: Should be invalid!" : "Correctly rejected");

        // Test with wrong key
        Console.Write("Testing wrong key... ");
        signer.GenerateKeyPair(out byte[] wrongPublicKey, out _);
        bool wrongKeyValid = signer.Verify(signature, wrongPublicKey, out _);
        Console.WriteLine(wrongKeyValid ? "ERROR: Should be invalid!" : "Correctly rejected");

        // Test hash function
        Console.Write("\nTesting hash function... ");
        byte[] hash = signer.Hash(message);
        Console.WriteLine("OK");
        Console.WriteLine($"  Hash:        {ToHex(hash, 32)}...\n");

        Console.WriteLine();
    }

    static string ToHex(byte[] data, int maxBytes = 0)
    {
        int len = maxBytes > 0 ? Math.Min(data.Length, maxBytes) : data.Length;
        var sb = new StringBuilder(len * 2);
        for (int i = 0; i < len; i++)
        {
            sb.Append(data[i].ToString("x2"));
        }
        return sb.ToString();
    }
}
