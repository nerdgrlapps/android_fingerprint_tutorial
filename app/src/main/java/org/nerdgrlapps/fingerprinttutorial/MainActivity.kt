package org.nerdgrlapps.fingerprinttutorial

import android.app.KeyguardManager
import android.content.Context
import android.os.Bundle
import android.preference.PreferenceManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.support.v4.os.CancellationSignal
import android.support.v7.app.AppCompatActivity
import android.util.Base64
import android.view.View
import android.widget.EditText
import android.widget.TextView
import java.nio.charset.Charset
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec

class MainActivity : AppCompatActivity() {

    companion object {
        val ANDROID_KEYSTORE = "AndroidKeyStore"
        val KEY_ALIAS = "mySecretKey"
    }

    private var mInput: EditText? = null
    private var mMessageOutput: TextView? = null
    private var mStatusOutput: TextView? = null
    private var mFingerprintMgr: FingerprintManagerCompat? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        mInput = findViewById(R.id.input)
        mMessageOutput = findViewById(R.id.message_output)
        mStatusOutput = findViewById(R.id.status_output)

        if(hasEncryptedMessage() && canUseFingerprints()) {
            loadSecretMessage()?.let {askFingerprintForDecryption(it)}
        }
    }

    public fun onSaveMessage(view: View) {
        val input = mInput?.text?.toString()?.trim()
        if(input == null || input.isEmpty()) {
            mStatusOutput?.text = "Cannot save empty message"
        } else {
            if(canUseFingerprints()) {
                askFingerprintForEncryption(input)
            }
        }
    }

    private fun saveSecretMessage(msg: String) {
        val prefs = PreferenceManager.getDefaultSharedPreferences(this)
        prefs.edit().putString("secret_message", msg).commit()
    }

    private fun loadSecretMessage(): String? {
        val prefs = PreferenceManager.getDefaultSharedPreferences(this)
        return prefs.getString("secret_message", null)
    }

    private fun displayMessageOutput(output: String) {
        mMessageOutput?.text = output
    }

    private fun resetStatusOutput() {
        mStatusOutput?.text = ""
    }

    private fun canUseFingerprints(): Boolean {
        val keyguardManager = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if(keyguardManager.isKeyguardSecure) {
            mFingerprintMgr = FingerprintManagerCompat.from(this)
            if(mFingerprintMgr?.isHardwareDetected == true) {
                if(mFingerprintMgr?.hasEnrolledFingerprints() == true) {
                    return true
                } else {
                    displayStatusOutput("No fingerprints were setup")
                }
            } else {
                displayStatusOutput("No fingerprint hardware")
            }
        } else {
            displayStatusOutput("User didn't setup any device lock")
        }
        return false
    }

    private fun displayStatusOutput(output: String) {
        mStatusOutput?.text = output
    }

    private fun generateNewKey() {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setUserAuthenticationRequired(true)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .build()
        keyGenerator.init(spec)
        keyGenerator.generateKey()
    }

    private fun askFingerprintForEncryption(input: String) {
        try {
            val keystore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keystore.load(null)

            if (!keystore.containsAlias(KEY_ALIAS)) generateNewKey()
            val key = keystore.getKey(KEY_ALIAS, null)

            val transformationString = "${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_CBC}/${KeyProperties.ENCRYPTION_PADDING_PKCS7}"
            var cipher = Cipher.getInstance(transformationString)

            try {
                cipher.init(KeyProperties.PURPOSE_ENCRYPT, key)
            } catch (exc: KeyPermanentlyInvalidatedException) {
                generateNewKey()
                val newKey = keystore.getKey(KEY_ALIAS, null)
                cipher = Cipher.getInstance(transformationString)
                cipher.init(KeyProperties.PURPOSE_ENCRYPT, newKey)
            }

            val cryptoObject = FingerprintManagerCompat.CryptoObject(cipher)
            val encryptionCallback = object : FingerprintManagerCompat.AuthenticationCallback() {
                override fun onAuthenticationError(errMsgId: Int, errString: CharSequence?) {
                    displayStatusOutput(errString?.toString() ?: "Unknown error")
                }

                override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?) {
                    displayStatusOutput("Success!")
                    result?.cryptoObject?.cipher?.let { encryptMessageWithCipher(input, it) }
                }

                override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?) {
                    displayStatusOutput(helpString?.toString() ?: "Unknown auth help message")
                }

                override fun onAuthenticationFailed() {
                    displayStatusOutput("Authentication failed")
                }
            }
            mFingerprintMgr?.authenticate(cryptoObject, 0, CancellationSignal(), encryptionCallback, null)
            displayStatusOutput("Touch the sensor")

        } catch (e: Exception) {
            e.printStackTrace()
            val errorMessage = e.message ?: "Unknown error"
            displayStatusOutput(errorMessage)
        }
    }

    private fun encryptMessageWithCipher(input: String, cipher: Cipher) {
        try {
            val iv = cipher.iv
            saveIV(iv)
            val encryptedContent = cipher.doFinal(input.toByteArray(Charset.forName("UTF-8")))
            val encryptedContentString = Base64.encodeToString(encryptedContent, 0)
            saveSecretMessage(encryptedContentString)
            displayMessageOutput("Encrypted message: $encryptedContentString\r\nOriginal message:$input")
            resetStatusOutput()
        } catch (e: Exception) {
            e.printStackTrace()
            val errorMessage = e.message ?: "Unknown error"
            displayStatusOutput(errorMessage)
        }
    }

    private fun saveIV(iv: ByteArray) {
        val ivString = Base64.encodeToString(iv, 0)
        val prefs = PreferenceManager.getDefaultSharedPreferences(this)
        prefs.edit().putString("iv", ivString).commit()
    }

    private fun loadIV(): ByteArray? {
        val prefs = PreferenceManager.getDefaultSharedPreferences(this)
        val ivString = prefs.getString("iv", null)
        ivString?.let { return Base64.decode(it, 0) }
        return null
    }

    private fun askFingerprintForDecryption(input: String) {
        try {
            val keystore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keystore.load(null)

            val key = keystore.getKey(KEY_ALIAS, null)
            if(key == null) {
                displayStatusOutput("Can't found key for decryption")
                return
            }

            val iv = loadIV()

            val cipher = Cipher.getInstance("${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_CBC}/${KeyProperties.ENCRYPTION_PADDING_PKCS7}")
            cipher.init(KeyProperties.PURPOSE_DECRYPT, key, IvParameterSpec(iv))
            val cryptoObject = FingerprintManagerCompat.CryptoObject(cipher)

            val decryptionCallback = object : FingerprintManagerCompat.AuthenticationCallback() {
                override fun onAuthenticationError(errMsgId: Int, errString: CharSequence?) {
                    displayStatusOutput(errString?.toString() ?: "Unknown error")
                }

                override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?) {
                    displayStatusOutput("Success!")
                    result?.cryptoObject?.cipher?.let { decryptMessageWithCipher(input, it) }
                }

                override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?) {
                    displayStatusOutput(helpString?.toString() ?: "Unknown auth help message")
                }

                override fun onAuthenticationFailed() {
                    displayStatusOutput("Authentication failed")
                }
            }

            mFingerprintMgr?.authenticate(cryptoObject, 0, CancellationSignal(), decryptionCallback, null)
            displayStatusOutput("Touch the sensor")
        } catch (e: Exception) {
            e.printStackTrace()
            val errorMessage = e.message ?: "Unknown error"
            displayStatusOutput(errorMessage)
        }
    }

    private fun decryptMessageWithCipher(encryptedMessage: String, cipher: Cipher) {
        try {
            val decryptedContent = cipher.doFinal(Base64.decode(encryptedMessage, 0))
            val decryptedContentString = String(decryptedContent, Charset.forName("UTF-8"))
            displayMessageOutput("Encrypted message: $encryptedMessage\r\nOriginal message:$decryptedContentString")
        } catch (e: Exception) {
            e.printStackTrace()
            val errorMessage = e.message ?: "Unknown error"
            displayStatusOutput(errorMessage)
        }
    }

    private fun hasEncryptedMessage(): Boolean {
        val secretMessage = loadSecretMessage()
        val keystore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keystore.load(null)
        return secretMessage != null && keystore.containsAlias(KEY_ALIAS)
    }

}
