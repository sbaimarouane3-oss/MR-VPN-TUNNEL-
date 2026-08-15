package com.sshproxy.vpn

import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.view.LayoutInflater
import android.view.View
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.sshproxy.vpn.importer.MlConfigFile
import com.sshproxy.vpn.importer.MlConfigParseException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * تبويب CONFIG: لائحة كل ملفات .ml المحفوظة فـ Downloads/MR VPN TUNNEL،
 * + زر أزرق كيدير كونفيغ جديد من الحقول الحالية فـ SSH SETTINGS.
 *
 * ماعندهاش أي منطق اتصال مباشر - كتعتمد كليا على MainActivity
 * (currentManualFieldsSnapshot / applyFieldsAndConnect) باش بروتوكول
 * الاتصال الحقيقي يبقى بلا تغيير.
 */
class ConfigFragment : Fragment(R.layout.fragment_config) {

    private lateinit var llConfigList: LinearLayout
    private lateinit var txtConfigEmpty: TextView
    private lateinit var btnAddConfig: View

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        llConfigList = view.findViewById(R.id.llConfigList)
        txtConfigEmpty = view.findViewById(R.id.txtConfigEmpty)
        btnAddConfig = view.findViewById(R.id.btnAddConfig)

        btnAddConfig.setOnClickListener { startCreateFlow() }

        (requireActivity() as? MainActivity)?.onConfigFragmentReady(this)
        refreshList()
    }

    fun refreshList() {
        val ctx = context ?: return
        lifecycleScope.launch {
            val entries = withContext(Dispatchers.IO) { ConfigStorageManager.list(ctx) }
            if (!isAdded) return@launch
            llConfigList.removeAllViews()
            txtConfigEmpty.visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE
            for (entry in entries) {
                llConfigList.addView(buildRow(entry))
            }
        }
    }

    private fun buildRow(entry: ConfigFileEntry): View {
        val row = LayoutInflater.from(requireContext()).inflate(R.layout.item_config_file, llConfigList, false)
        val txtName = row.findViewById<TextView>(R.id.txtConfigName)
        val txtMeta = row.findViewById<TextView>(R.id.txtConfigMeta)
        val imgLock = row.findViewById<ImageView>(R.id.imgConfigLock)

        val displayName = entry.displayName.removeSuffix(".${MlConfigFile.EXTENSION}")
        txtName.text = displayName
        txtMeta.text = if (entry.isEncrypted) "\uD83D\uDD12 Password protected" else "Unprotected \u2022 tap & hold for options"
        imgLock.setColorFilter(
            ContextCompat.getColor(requireContext(), if (entry.isEncrypted) R.color.state_error else R.color.accent_green)
        )

        row.setOnClickListener { openEntry(entry) }
        row.setOnLongClickListener { showEntryMenu(entry); true }
        return row
    }

    // ===== فتح ملف (تاب داخل CONFIG، أو جاي من نية VIEW خارجية) =====

    private fun openEntry(entry: ConfigFileEntry) {
        val ctx = context ?: return
        lifecycleScope.launch {
            val bytes = withContext(Dispatchers.IO) { ConfigStorageManager.readBytes(ctx, entry.uri) }
            if (bytes == null) {
                Toast.makeText(ctx, "Could not read file.", Toast.LENGTH_SHORT).show()
                return@launch
            }
            if (entry.isEncrypted) {
                promptPasswordAndOpen(bytes)
            } else {
                applyParsedConfig(bytes, null, isProtected = false)
            }
        }
    }

    private fun promptPasswordAndOpen(bytes: ByteArray) {
        val ctx = context ?: return
        val input = EditText(ctx).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = "Password"
        }
        AlertDialog.Builder(ctx)
            .setTitle("Protected Config")
            .setMessage("This config is password protected. Enter the password to open it.")
            .setView(wrapDialogInput(input))
            .setPositiveButton("Open") { _, _ -> applyParsedConfig(bytes, input.text.toString(), isProtected = true) }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun applyParsedConfig(bytes: ByteArray, password: String?, isProtected: Boolean) {
        val ctx = context ?: return
        try {
            val parsed = MlConfigFile.parse(bytes, password)
            (requireActivity() as? MainActivity)?.applyFieldsAndConnect(parsed.fields, parsed.serverMessage, isProtected)
        } catch (e: MlConfigParseException) {
            val msg = if (e.message == "wrong password") "Wrong password." else "Invalid or corrupted config file."
            Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show()
        } catch (_: Throwable) {
            Toast.makeText(ctx, "Invalid or corrupted config file.", Toast.LENGTH_SHORT).show()
        }
    }

    // ===== قائمة الضغط المطول: Edit/Delete/Share (بلا كلمة سر) أو Delete/Share (بكلمة سر) =====

    private fun showEntryMenu(entry: ConfigFileEntry) {
        val ctx = context ?: return
        val actions = if (entry.isEncrypted) listOf("Delete", "Share") else listOf("Edit", "Delete", "Share")
        AlertDialog.Builder(ctx)
            .setTitle(entry.displayName.removeSuffix(".${MlConfigFile.EXTENSION}"))
            .setItems(actions.toTypedArray()) { _, which ->
                when (actions[which]) {
                    "Edit" -> editEntry(entry)
                    "Delete" -> confirmDelete(entry)
                    "Share" -> shareEntry(entry)
                }
            }
            .show()
    }

    private fun editEntry(entry: ConfigFileEntry) {
        val ctx = context ?: return
        lifecycleScope.launch {
            val bytes = withContext(Dispatchers.IO) { ConfigStorageManager.readBytes(ctx, entry.uri) }
            if (bytes == null) {
                Toast.makeText(ctx, "Could not read file.", Toast.LENGTH_SHORT).show()
                return@launch
            }
            try {
                val parsed = MlConfigFile.parse(bytes, null)
                (requireActivity() as? MainActivity)?.loadFieldsForEditing(parsed.fields)
                val baseName = entry.displayName.removeSuffix(".${MlConfigFile.EXTENSION}")
                Toast.makeText(
                    ctx,
                    "Loaded into SSH SETTINGS. Edit the fields, then tap + here and use the same name \"$baseName\" to overwrite it.",
                    Toast.LENGTH_LONG
                ).show()
            } catch (_: Throwable) {
                Toast.makeText(ctx, "Could not load config for editing.", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun confirmDelete(entry: ConfigFileEntry) {
        val ctx = context ?: return
        AlertDialog.Builder(ctx)
            .setTitle("Delete Config")
            .setMessage("Delete \"${entry.displayName}\"? This cannot be undone.")
            .setPositiveButton("Delete") { _, _ ->
                lifecycleScope.launch {
                    val ok = withContext(Dispatchers.IO) { ConfigStorageManager.delete(ctx, entry) }
                    if (!ok) Toast.makeText(ctx, "Could not delete file.", Toast.LENGTH_SHORT).show()
                    refreshList()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun shareEntry(entry: ConfigFileEntry) {
        val ctx = context ?: return
        try {
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "application/octet-stream"
                putExtra(Intent.EXTRA_STREAM, entry.uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(intent, "Share Config"))
        } catch (_: Throwable) {
            Toast.makeText(ctx, "Could not share file.", Toast.LENGTH_SHORT).show()
        }
    }

    // ===== إنشاء كونفيغ جديد: اسم -> كلمة سر (اختياري) -> سيرفر مساج (اختياري) =====

    private fun startCreateFlow() {
        val ctx = context ?: return
        val nameInput = EditText(ctx).apply { hint = "Config name (any text/emoji)" }
        AlertDialog.Builder(ctx)
            .setTitle("New Config")
            .setMessage("Name this config. It will be created from your current SSH SETTINGS.")
            .setView(wrapDialogInput(nameInput))
            .setPositiveButton("Next") { _, _ ->
                val name = nameInput.text.toString().trim()
                if (name.isEmpty()) {
                    Toast.makeText(ctx, "Please enter a name.", Toast.LENGTH_SHORT).show()
                } else {
                    askPasswordStep(name)
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun askPasswordStep(name: String) {
        val ctx = context ?: return
        val passInput = EditText(ctx).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = "Password (optional - leave empty for no protection)"
        }
        AlertDialog.Builder(ctx)
            .setTitle("Protect with a Password?")
            .setMessage("If you set a password, the file will be strongly encrypted (AES-256) and no one can read the server info inside without it. Leave empty to keep the file open/editable.")
            .setView(wrapDialogInput(passInput))
            .setPositiveButton("Next") { _, _ -> askServerMessageStep(name, passInput.text.toString()) }
            .setNegativeButton("Back") { _, _ -> startCreateFlow() }
            .show()
    }

    private fun askServerMessageStep(name: String, password: String) {
        val ctx = context ?: return
        val msgInput = EditText(ctx).apply { hint = "Server message shown on connect (optional)" }
        AlertDialog.Builder(ctx)
            .setTitle("Server Message")
            .setMessage("Optional message shown at the bottom of the screen when this config connects.")
            .setView(wrapDialogInput(msgInput))
            .setPositiveButton("Save") { _, _ -> saveConfig(name, password, msgInput.text.toString()) }
            .setNegativeButton("Back") { _, _ -> askPasswordStep(name) }
            .show()
    }

    private fun saveConfig(name: String, password: String, serverMessage: String) {
        val ctx = context ?: return
        val activity = requireActivity() as? MainActivity ?: return
        val fields = activity.currentManualFieldsSnapshot()
        val bytes = MlConfigFile.build(name, serverMessage.trim(), fields, password.ifBlank { null })
        val fileName = ConfigStorageManager.finalFileName(name)

        lifecycleScope.launch {
            val existing = withContext(Dispatchers.IO) { ConfigStorageManager.list(ctx) }
                .firstOrNull { it.displayName.equals(fileName, ignoreCase = true) }

            fun doSave() {
                lifecycleScope.launch {
                    val ok = withContext(Dispatchers.IO) {
                        if (existing != null) ConfigStorageManager.overwrite(ctx, existing, bytes)
                        else ConfigStorageManager.save(ctx, name, bytes) != null
                    }
                    if (ok) {
                        Toast.makeText(ctx, "Config saved to Download/MR VPN TUNNEL \u2705", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(ctx, "Could not save config.", Toast.LENGTH_SHORT).show()
                    }
                    refreshList()
                }
            }

            if (existing != null) {
                AlertDialog.Builder(ctx)
                    .setTitle("Replace existing config?")
                    .setMessage("A config named \"$fileName\" already exists. Overwrite it?")
                    .setPositiveButton("Replace") { _, _ -> doSave() }
                    .setNegativeButton("Cancel", null)
                    .show()
            } else {
                doSave()
            }
        }
    }

    private fun wrapDialogInput(input: EditText): View {
        val padding = (16 * resources.displayMetrics.density).toInt()
        return LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(padding, padding / 2, padding, 0)
            addView(input)
        }
    }
}
