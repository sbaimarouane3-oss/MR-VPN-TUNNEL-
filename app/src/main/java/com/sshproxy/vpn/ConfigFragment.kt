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
 * تبويب CONFIG: لائحة كل ملفات .ml المحفوظة فـ Downloads/MR VPN TUNNEL.
 * الزر ★ فوسط كل صف كيبدا/كيوقف الاتصال بهاد الكونفيغ بالضبط بلا ما
 * نخرجو من هاد التبويب (شوف MainActivity.connectConfigFile /
 * disconnectConfigFile). الضغط على جسم الصف كيبين/كيخبي لوحة موسعة
 * (Info + Edit/Share/Delete) فنفس المكان - بلا Dialog وبلا تبديل تبويب.
 * إنشاء كونفيغ جديد صار من زر "+ NEW CONFIG" فـ SSH SETTINGS، ماشي من هنا.
 */
class ConfigFragment : Fragment(R.layout.fragment_config) {

    private lateinit var llConfigList: LinearLayout
    private lateinit var txtConfigEmpty: TextView

    // كاش خفيف للصفوف المبنية دابا - باش updateActiveVisuals() يقدر
    // يبدل لون/أيقونة الصف النشط بلا ما يعاود يقرا من القرص فكل مرة
    // الحالة (Connecting/Connected/Disconnected) كتبدل.
    private val rowViews = mutableMapOf<String, View>()
    private val expandedNames = mutableSetOf<String>()

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        llConfigList = view.findViewById(R.id.llConfigList)
        txtConfigEmpty = view.findViewById(R.id.txtConfigEmpty)

        (requireActivity() as? MainActivity)?.onConfigFragmentReady(this)
        refreshList()
    }

    fun refreshList() {
        val ctx = context ?: return
        val activity = requireActivity() as? MainActivity
        lifecycleScope.launch {
            val entries = withContext(Dispatchers.IO) { ConfigStorageManager.list(ctx) }
            if (!isAdded) return@launch
            llConfigList.removeAllViews()
            rowViews.clear()
            txtConfigEmpty.visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE
            for (entry in entries) {
                val row = buildRow(entry)
                rowViews[entry.displayName] = row
                llConfigList.addView(row)
            }
            val activeName = activity?.activeConfigFileNameOrNull()
            if (activeName != null) {
                updateActiveVisuals(activeName, activity?.isConnectedNow() ?: false, activity?.isConnectingNow() ?: false)
            }
        }
    }

    /**
     * كتبدل غير الشكل البصري (لون الصف + أيقونة ★/■) حسب الحالة الحالية -
     * بلا ما تعاود تقرا الملفات من القرص. MainActivity كتناديها كل مرة
     * connected/connecting كيتبدلو فعليا.
     */
    fun updateActiveVisuals(activeName: String?, connected: Boolean, connecting: Boolean) {
        if (!isAdded) return
        for ((name, row) in rowViews) {
            val rowCard = row.findViewById<View>(R.id.rowConfigItem)
            val actionBg = row.findViewById<View>(R.id.btnConfigAction)
            val actionIcon = row.findViewById<ImageView>(R.id.imgConfigAction)
            val isThisOne = name == activeName
            if (isThisOne && (connected || connecting)) {
                rowCard.setBackgroundResource(R.drawable.shape_card_active)
                if (connected) {
                    // 🟢 أخضر = توقف بعد نجاح الاتصال.
                    actionBg.setBackgroundResource(R.drawable.shape_config_action_green)
                    actionIcon.setImageResource(R.drawable.ic_stop_square)
                } else {
                    // 🔴 أحمر = توقف أثناء بدء/محاولة الاتصال (الضغط عليه
                    // كيلغي المحاولة، نفس disconnect() ديال الاتصال العادي).
                    actionBg.setBackgroundResource(R.drawable.shape_config_action_red)
                    actionIcon.setImageResource(R.drawable.ic_stop_square)
                }
            } else {
                // 🔵 أزرق = تشغيل (لا اتصال حالي بهاد الملف).
                rowCard.setBackgroundResource(R.drawable.shape_card_alt)
                actionBg.setBackgroundResource(R.drawable.shape_config_action_blue)
                actionIcon.setImageResource(R.drawable.ic_play)
            }
        }
    }

    private fun buildRow(entry: ConfigFileEntry): View {
        val row = LayoutInflater.from(requireContext()).inflate(R.layout.item_config_file, llConfigList, false)
        val txtName = row.findViewById<TextView>(R.id.txtConfigName)
        val txtMeta = row.findViewById<TextView>(R.id.txtConfigMeta)
        val imgLock = row.findViewById<ImageView>(R.id.imgConfigLock)
        val rowCard = row.findViewById<View>(R.id.rowConfigItem)
        val btnAction = row.findViewById<View>(R.id.btnConfigAction)
        val expandPanel = row.findViewById<LinearLayout>(R.id.expandConfigPanel)
        val txtInfo = row.findViewById<TextView>(R.id.txtConfigInfo)
        val btnEdit = row.findViewById<View>(R.id.btnConfigEdit)
        val btnShare = row.findViewById<View>(R.id.btnConfigShare)
        val btnDelete = row.findViewById<View>(R.id.btnConfigDelete)

        val displayName = entry.displayName.removeSuffix(".${MlConfigFile.EXTENSION}")
        txtName.text = displayName
        txtMeta.text = if (entry.isEncrypted) "Password protected" else "Unprotected \u2022 tap for details"
        imgLock.setImageResource(if (entry.isEncrypted) R.drawable.ic_lock else R.drawable.ic_check_circle)
        imgLock.setColorFilter(
            ContextCompat.getColor(requireContext(), if (entry.isEncrypted) R.color.state_error else R.color.accent_green)
        )

        // Edit دابا متاح لكل الملفات (محمية ولا لا) - password إجباري
        // على كل حفظ جديد دابا، فما بقاش داعي نمنعو Edit على الملفات
        // المحمية (كان قبل هادشي بحيث الحفظ القديم كان بلا password إلا
        // لأصلا الملف بلا password). editEntry() تحت كتطلب password أولا
        // إلا كان الملف محمي.
        btnEdit.visibility = View.VISIBLE

        btnAction.setOnClickListener { onActionTapped(entry) }

        rowCard.setOnClickListener {
            if (expandedNames.contains(entry.displayName)) {
                expandedNames.remove(entry.displayName)
                expandPanel.visibility = View.GONE
            } else {
                expandedNames.add(entry.displayName)
                expandPanel.visibility = View.VISIBLE
                txtInfo.text = if (entry.isEncrypted) {
                    "This config is password protected. Editing requires the password - sharing and deleting are always available."
                } else {
                    "Unprotected config. You can edit its fields, share the file, or delete it."
                }
            }
        }

        btnEdit.setOnClickListener { editEntry(entry) }
        btnShare.setOnClickListener { shareEntry(entry) }
        btnDelete.setOnClickListener { confirmDelete(entry) }

        return row
    }

    // ===== زر ★/■: بدء/وقف الاتصال بهاد الكونفيغ بالضبط، بلا مغادرة CONFIG tab =====

    private fun onActionTapped(entry: ConfigFileEntry) {
        val ctx = context ?: return
        val activity = requireActivity() as? MainActivity ?: return

        if (activity.isConfigFileActive(entry.displayName) && (activity.isConnectedNow() || activity.isConnectingNow())) {
            activity.disconnectConfigFile()
            return
        }

        // إلا كان هاد الملف بالضبط هو ديجا الكونفيغ المحمل عند
        // MainActivity (activeConfigFileName + SAVED_CONFIG) - سواء بقا
        // محمل من نفس الجلسة، أو تسترجع من SecureConfigStore/
        // XraySecureConfigStore عند إعادة فتح التطبيق (حتى بعد ما
        // process تقتل بالكامل، شوف MainActivity.onCreate) - كنشغلوه
        // مباشرة بلا ما نعاودو نقرا/نفكو الملف من القرص، وبلا password.
        // هادشي كيغطي بالضبط الحالة لي كان فيها UnlockedConfigCache
        // (فارغة بعد process kill) كتخلي password يتطلب بلا داعي رغم
        // أن MainActivity ديجا عندها نفس الكونفيغ محفوظ محليا.
        if (activity.startIfAlreadyLoaded(entry.displayName)) return

        lifecycleScope.launch {
            val bytes = withContext(Dispatchers.IO) { ConfigStorageManager.readBytes(ctx, entry.uri) }
            if (bytes == null) {
                Toast.makeText(ctx, "Could not read file.", Toast.LENGTH_SHORT).show()
                return@launch
            }
            if (entry.isEncrypted) {
                val cached = UnlockedConfigCache.get(entry.displayName)
                if (cached != null) {
                    activity.connectConfigFile(entry.displayName, cached, isProtected = true)
                } else {
                    promptPasswordAndConnect(entry, bytes)
                }
            } else {
                try {
                    val parsed = withContext(Dispatchers.Default) { MlConfigFile.parse(bytes, null) }
                    activity.connectConfigFile(entry.displayName, parsed.fields, isProtected = false)
                } catch (_: Throwable) {
                    Toast.makeText(ctx, "Invalid or corrupted config file.", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun promptPasswordAndConnect(entry: ConfigFileEntry, bytes: ByteArray) {
        val ctx = context ?: return
        val input = EditText(ctx).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = "Password"
        }
        AlertDialog.Builder(ctx)
            .setTitle("Protected Config")
            .setMessage("Enter the password to connect. You'll only need to enter it once this session - the file stays locked, but you won't be asked again while the app is open.")
            .setView(wrapDialogInput(input))
            .setPositiveButton("Connect") { _, _ ->
                val password = input.text.toString()
                val activity = requireActivity() as? MainActivity ?: return@setPositiveButton
                lifecycleScope.launch {
                    try {
                        val parsed = withContext(Dispatchers.Default) { MlConfigFile.parse(bytes, password) }
                        UnlockedConfigCache.put(entry.displayName, parsed.fields)
                        activity.connectConfigFile(entry.displayName, parsed.fields, isProtected = true)
                    } catch (_: MlConfigParseException) {
                        Toast.makeText(ctx, "Wrong password.", Toast.LENGTH_SHORT).show()
                    } catch (_: Throwable) {
                        Toast.makeText(ctx, "Wrong password.", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // ===== لوحة موسعة: Edit / Share / Delete (Edit غير للملفات بلا كلمة سر) =====

    private fun editEntry(entry: ConfigFileEntry) {
        val ctx = context ?: return
        if (entry.isEncrypted) {
            val cached = UnlockedConfigCache.get(entry.displayName)
            if (cached != null) {
                (requireActivity() as? MainActivity)?.loadFieldsForEditing(entry.displayName, cached)
                Toast.makeText(ctx, "Loaded into SSH SETTINGS for editing. Use + NEW CONFIG to save your changes.", Toast.LENGTH_LONG).show()
            } else {
                promptPasswordForEdit(entry)
            }
            return
        }
        lifecycleScope.launch {
            val bytes = withContext(Dispatchers.IO) { ConfigStorageManager.readBytes(ctx, entry.uri) }
            if (bytes == null) {
                Toast.makeText(ctx, "Could not read file.", Toast.LENGTH_SHORT).show()
                return@launch
            }
            try {
                val parsed = MlConfigFile.parse(bytes, null)
                (requireActivity() as? MainActivity)?.loadFieldsForEditing(entry.displayName, parsed.fields)
                Toast.makeText(ctx, "Loaded into SSH SETTINGS for editing. Use + NEW CONFIG to save your changes.", Toast.LENGTH_LONG).show()
            } catch (_: Throwable) {
                Toast.makeText(ctx, "Could not load config for editing.", Toast.LENGTH_SHORT).show()
            }
        }
    }

    /** بحال promptPasswordAndConnect لكن الهدف Edit ماشي Connect - نفس UnlockedConfigCache. */
    private fun promptPasswordForEdit(entry: ConfigFileEntry) {
        val ctx = context ?: return
        val input = EditText(ctx).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = "Password"
        }
        AlertDialog.Builder(ctx)
            .setTitle("Protected Config")
            .setMessage("Enter the password to edit this config.")
            .setView(wrapDialogInput(input))
            .setPositiveButton("Continue") { _, _ ->
                val password = input.text.toString()
                lifecycleScope.launch {
                    val bytes = withContext(Dispatchers.IO) { ConfigStorageManager.readBytes(ctx, entry.uri) }
                    if (bytes == null) {
                        Toast.makeText(ctx, "Could not read file.", Toast.LENGTH_SHORT).show()
                        return@launch
                    }
                    try {
                        val parsed = withContext(Dispatchers.Default) { MlConfigFile.parse(bytes, password) }
                        UnlockedConfigCache.put(entry.displayName, parsed.fields)
                        (requireActivity() as? MainActivity)?.loadFieldsForEditing(entry.displayName, parsed.fields)
                        Toast.makeText(ctx, "Loaded into SSH SETTINGS for editing. Use + NEW CONFIG to save your changes.", Toast.LENGTH_LONG).show()
                    } catch (_: MlConfigParseException) {
                        Toast.makeText(ctx, "Wrong password.", Toast.LENGTH_SHORT).show()
                    } catch (_: Throwable) {
                        Toast.makeText(ctx, "Wrong password.", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun confirmDelete(entry: ConfigFileEntry) {
        val ctx = context ?: return
        val activity = requireActivity() as? MainActivity
        AlertDialog.Builder(ctx)
            .setTitle("Delete Config")
            .setMessage("Delete \"${entry.displayName}\"? This cannot be undone.")
            .setPositiveButton("Delete") { _, _ ->
                lifecycleScope.launch {
                    UnlockedConfigCache.remove(entry.displayName)
                    val ok = withContext(Dispatchers.IO) { ConfigStorageManager.delete(ctx, entry) }
                    if (!ok) Toast.makeText(ctx, "Could not delete file.", Toast.LENGTH_SHORT).show()
                    activity?.handleConfigFileDeleted(entry.displayName)
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

    private fun wrapDialogInput(input: EditText): View {
        val padding = (16 * resources.displayMetrics.density).toInt()
        return LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(padding, padding / 2, padding, 0)
            addView(input)
        }
    }
}
