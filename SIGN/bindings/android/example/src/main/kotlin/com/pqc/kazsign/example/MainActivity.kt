/*
 * KAZ-SIGN Android Example
 *
 * Demonstrates key generation, signing, and verification
 * using the KAZ-SIGN post-quantum signature library.
 */

package com.pqc.kazsign.example

import android.os.Bundle
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.pqc.kazsign.*
import com.pqc.kazsign.example.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private var currentLevel: SecurityLevel = SecurityLevel.LEVEL_128
    private var currentKeyPair: KeyPair? = null
    private var currentSignature: ByteArray? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupUI()
        showVersion()
    }

    private fun setupUI() {
        // Setup security level spinner
        val levels = SecurityLevel.entries.map { "${it.name} (${it.value}-bit)" }
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, levels)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        binding.spinnerLevel.adapter = adapter

        binding.spinnerLevel.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                currentLevel = SecurityLevel.entries[position]
                clearState()
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        // Button click handlers
        binding.btnGenerateKeys.setOnClickListener { generateKeyPair() }
        binding.btnSign.setOnClickListener { signMessage() }
        binding.btnVerify.setOnClickListener { verifySignature() }
        binding.btnClear.setOnClickListener { clearState() }
    }

    private fun showVersion() {
        lifecycleScope.launch {
            try {
                val version = withContext(Dispatchers.IO) {
                    KazSigner.version
                }
                binding.tvVersion.text = "KAZ-SIGN v$version"
            } catch (e: Exception) {
                binding.tvVersion.text = "Version: Error loading library"
            }
        }
    }

    private fun generateKeyPair() {
        lifecycleScope.launch {
            try {
                setLoading(true)
                binding.tvResult.text = "Generating key pair..."

                val keyPair = withContext(Dispatchers.IO) {
                    kazSigner(currentLevel) {
                        generateKeyPair()
                    }
                }

                currentKeyPair = keyPair
                currentSignature = null

                binding.tvPublicKey.text = keyPair.publicKeyHex.take(64) + "..."
                binding.tvSignature.text = ""
                binding.btnSign.isEnabled = true
                binding.btnVerify.isEnabled = false

                showSuccess("Key pair generated successfully!\n" +
                        "Public key: ${keyPair.publicKey.size} bytes\n" +
                        "Secret key: ${keyPair.secretKey.size} bytes")

            } catch (e: Exception) {
                showError("Key generation failed: ${e.message}")
            } finally {
                setLoading(false)
            }
        }
    }

    private fun signMessage() {
        val keyPair = currentKeyPair ?: return
        val message = binding.etMessage.text?.toString() ?: return

        if (message.isEmpty()) {
            showError("Please enter a message to sign")
            return
        }

        lifecycleScope.launch {
            try {
                setLoading(true)
                binding.tvResult.text = "Signing message..."

                val result = withContext(Dispatchers.IO) {
                    kazSigner(currentLevel) {
                        sign(message, keyPair.secretKey)
                    }
                }

                currentSignature = result.signature

                binding.tvSignature.text = result.signatureHex.take(80) + "..."
                binding.btnVerify.isEnabled = true

                showSuccess("Message signed successfully!\n" +
                        "Signature: ${result.signature.size} bytes\n" +
                        "Overhead: ${result.overhead} bytes")

            } catch (e: Exception) {
                showError("Signing failed: ${e.message}")
            } finally {
                setLoading(false)
            }
        }
    }

    private fun verifySignature() {
        val keyPair = currentKeyPair ?: return
        val signature = currentSignature ?: return

        lifecycleScope.launch {
            try {
                setLoading(true)
                binding.tvResult.text = "Verifying signature..."

                val result = withContext(Dispatchers.IO) {
                    kazSigner(currentLevel) {
                        verify(signature, keyPair.publicKey)
                    }
                }

                if (result.isValid) {
                    val recoveredMessage = result.getMessageAsString() ?: "(binary data)"
                    showSuccess("Signature VALID!\n\nRecovered message:\n\"$recoveredMessage\"")
                } else {
                    showError("Signature INVALID!")
                }

            } catch (e: Exception) {
                showError("Verification failed: ${e.message}")
            } finally {
                setLoading(false)
            }
        }
    }

    private fun clearState() {
        currentKeyPair = null
        currentSignature = null

        binding.tvPublicKey.text = ""
        binding.tvSignature.text = ""
        binding.tvResult.text = ""
        binding.btnSign.isEnabled = false
        binding.btnVerify.isEnabled = false
    }

    private fun setLoading(loading: Boolean) {
        binding.btnGenerateKeys.isEnabled = !loading
        binding.btnSign.isEnabled = !loading && currentKeyPair != null
        binding.btnVerify.isEnabled = !loading && currentSignature != null
        binding.spinnerLevel.isEnabled = !loading
    }

    private fun showSuccess(message: String) {
        binding.tvResult.text = message
        binding.tvResult.setTextColor(ContextCompat.getColor(this, R.color.success))
    }

    private fun showError(message: String) {
        binding.tvResult.text = message
        binding.tvResult.setTextColor(ContextCompat.getColor(this, R.color.error))
    }
}
