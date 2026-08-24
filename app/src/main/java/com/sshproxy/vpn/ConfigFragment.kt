package com.sshproxy.vpn

import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.view.DragEvent
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
import org.json.JSONArray

/**
 * تبويب CONFIG: لائحة كل ملفات .ml المحفوظة فـ Downloads/MR VPN TUNNEL.
 * الزر ★ فوسط كل صف كيبدا/كيوقف الاتصال بهاد الكونفيغ بالضبط بلا ما
 * نخرجو من هاد التبويب (شوف MainActivity.connectConfigFile /
 * disconnectConfigFile). الضغط على جسم الصف كيبين/كيخبي لوحة موسعة
 * (Info + Edit/Share/Delete) فنفس المكان - بلا Dialog وبلا تبديل تبويب.
 * إنشاء كونفيغ جديد صار من زر "+ NEW CONFIG" فـ SSH SETTINGS، ماشي من هنا.
 *
 * الضغط الطويل على جسم الصف كيبدا سحب (Drag & Drop) باش المستخدم يقدر
 * يرتب الملفات بيدو (مفيد بزاف ملي كيتزادو بزاف ملفات) - شوف
 * setupDragAndDrop/persistCurrentOrder/applySavedOrder تحت. الترتيب
 * كيتحفظ فـSharedPreferences محلية (ماشي فالملفات نفسهم)، وكيبقى محفوظ
 * حتى بعد إغلاق التطبيق. ملفات جداد (بلا ترتيب مسجل بعد) كيبانو فالأعلى
 * بشكل طبيعي، بحال السلوك الافتراضي القديم (الأحدث فوق).
 */
class ConfigFragment : Fragment(R.layout.fragment_config) {

    private lateinit var llConfigList: LinearLayout
    private lateinit var txtConfigEmpty: TextView

    // كاش خفيف للصفوف المبنية دابا - باش updateActiveVisuals() يقدر
    // يبدل لون/أيقونة الصف النشط بلا ما يعاود يقرا من القرص فكل مرة
    // الحالة (Connecting/Connected/Disconnected) كتبدل.
    private val rowViews = mutableMapOf<String, View>()
    private val expandedNames = mutableSetOf<String>()

    // ===== Drag & Drop (ترتيب يدوي بالضغط الطويل) =====
    private var draggedRow: View? = null
    private var draggedName: String? = null

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        llConfigList = view.findViewById(R.id.llConfigList)
        txtConfigEmpty = view.findViewById(R.id.txtConfigEmpty)

        (requireActivity() as? MainActivity)?.onConfigFragmentReady(this)
        setupDragAndDrop()
        refreshList()
    }

    fun refreshList() {
        val ctx = context ?: return
        val activity = requireActivity() as? MainActivity
        lifecycleScope.launch {
            val entries = withContext(Dispatchers.IO) { ConfigStorageManager.list(ctx) }
            if (!isAdded) return@launch
            val ordered = applySavedOrder(entries)
            llConfigList.removeAllViews()
            rowViews.clear()
            txtConfigEmpty.visibility = if (ordered.isEmpty()) View.VISIBLE else View.GONE
            for (entry in ordered) {
                val row = buildRow(entry)
                rowViews[entry.displayName] = row
                llConfigList.addView(row)
            }
            // FIX (مشكلة 3): قبل هاد التصحيح، updateActiveVisuals() كانت
            // كتندى غير ملي activeName != null - يعني إلا رجعت
            // activeConfigFileName لـnull بطريقة غير متوقعة (مثلا بسبب
            // mismatch مؤقت بين Connection Source و Config Source - شوف
            // فيكس مشكلة 2)، كل الصفوف الجداد المبنية دابا كانت كتبقى
            // بالحالة الافتراضية بلا أي مزامنة صريحة مع الحالة الحقيقية.
            // دابا كندّيو updateActiveVisuals() دايما، بلا شرط - هادشي
            // كيضمن: كل ملف غير نشط عندو START ظاهر دايما، والملف النشط
            // فقط هو لي كيبين RUNNING/STOP - بلا ما نخفيو ولا نمسحو حتى
            // ملف من اللائحة.
            val activeName = activity?.activeConfigFileNameOrNull()
            updateActiveVisuals(
                activeName,
                activity?.isConnectedNow() ?: false,
                activity?.isConnectingNow() ?: false,
                activity?.isReconnectingNow() ?: false
            )
        }
    }

    /**
     * كتبدل غير الشكل البصري (لون الصف + أيقونة ★/■) حسب الحالة الحالية -
     * بلا ما تعاود تقرا الملفات من القرص. MainActivity كتناديها كل مرة
     * connected/connecting كيتبدلو فعليا.
     */
    fun updateActiveVisuals(activeName: String?, connected: Boolean, connecting: Boolean, reconnecting: Boolean = false) {
        if (!isAdded) return
        // true غير ملي كاين فعلا ملف نشط (متصل أو فطور الاتصال) - هادشي
        // كيفرق بين "ما كاين حتى اتصال" (كلشي START) و"كاين اتصال بملف
        // معين" (هو STOP/RUNNING، الباقي زر START ديالهم كيتخبى مؤقتا
        // بلا ما يتخبى الـRow نفسو - شوف التعديل الأخير المطلوب).
        // FIX (فليكر ديال الأيقونات): reconnecting (RECONNECTING/
        // WAITING_NETWORK) خاصها تتحسب هي زادة كـ"ملف نشط" - قبل هاد
        // الفيكس كانت كتنسى، فملي الاتصال كيدخل RECONNECTING (شبه عادي
        // فوقت البداية أو الStop)، hasActiveFile كانت كترجع false، فكل
        // الصفوف كانو كيرجعو للأزرق (START) لحظة وحدة قبل ما يرجعو
        // للحالة الصحيحة - هادشي هو الفليكر.
        val hasActiveFile = activeName != null && (connected || connecting || reconnecting)
        for ((name, row) in rowViews) {
            val rowCard = row.findViewById<View>(R.id.rowConfigItem)
            val actionBg = row.findViewById<View>(R.id.btnConfigAction)
            val actionIcon = row.findViewById<ImageView>(R.id.imgConfigAction)
            val isThisOne = name == activeName
            if (isThisOne && hasActiveFile) {
                // الملف النشط: ظاهر + زر STOP/RUNNING ظاهر وقابل للضغط.
                rowCard.setBackgroundResource(R.drawable.shape_card_active)
                actionBg.visibility = View.VISIBLE
                actionBg.isEnabled = true
                actionBg.isClickable = true
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
            } else if (hasActiveFile) {
                // ملف آخر (ماشي هو النشط) وكاين اتصال جاري بملف مختلف:
                // الـRow بحالو يبقى ظاهر بالكامل (الاسم، الميتا، Edit/Share/
                // Delete...) - كنخبيو غير زر ▶️ START ديالو مؤقتا (INVISIBLE
                // كيخلي نفس المكان محجوز باش التصميم مايهزش)، وكنعطلو
                // الضغط عليه باش ما يمكنش يبدا اتصال ثاني بملف تاني وملف
                // واحد ديجا خدام.
                rowCard.setBackgroundResource(R.drawable.shape_card_alt)
                actionBg.visibility = View.INVISIBLE
                actionBg.isEnabled = false
                actionBg.isClickable = false
            } else {
                // ما كاين حتى ملف نشط: 🔵 أزرق = START ظاهر للجميع.
                rowCard.setBackgroundResource(R.drawable.shape_card_alt)
                actionBg.visibility = View.VISIBLE
                actionBg.isEnabled = true
                actionBg.isClickable = true
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

        // Edit خاصو يكون متاح غير لملف مملوك لهذا الجهاز.
        // التحقق الحقيقي كيدوز داخل editEntry() بعد فك الملف والتحقق من التوقيع.
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
                    "Password protected. Only the device that created this config can edit it. Other devices can connect and share it."
                } else {
                    "Only the device that created this config can edit it. Other devices can connect and share it."
                }
            }
        }

        // الضغط الطويل على جسم الصف كيبدا سحب لترتيب الملفات - نفس المبدأ
        // ديال "long press to reorder" فمعظم التطبيقات (بحال WhatsApp/
        // Play Music). ماكيتعارضش مع rowCard.setOnClickListener فوق
        // (توسيع اللوحة) - Android كيدير الفرق بين tap عادي وlong press
        // تلقائيا (الحدث كيتلقى غير واحد منهم حسب مدة الضغط).
        rowCard.setOnLongClickListener {
            draggedRow = row
            draggedName = entry.displayName
            val shadow = View.DragShadowBuilder(row)
            row.alpha = 0.35f
            row.startDragAndDrop(null, shadow, entry.displayName, 0)
            true
        }

        btnEdit.setOnClickListener { editEntry(entry) }
        btnShare.setOnClickListener { shareEntry(entry) }
        btnDelete.setOnClickListener { confirmDelete(entry) }

        return row
    }

    // ===== Drag & Drop: تحريك الصف حي فوسط llConfigList، وحفظ الترتيب =====

    private fun setupDragAndDrop() {
        llConfigList.setOnDragListener { _, event ->
            when (event.action) {
                DragEvent.ACTION_DRAG_STARTED -> true
                DragEvent.ACTION_DRAG_LOCATION -> {
                    handleDragLocation(event.y)
                    true
                }
                DragEvent.ACTION_DROP -> true
                DragEvent.ACTION_DRAG_ENDED -> {
                    draggedRow?.alpha = 1f
                    draggedRow = null
                    draggedName = null
                    persistCurrentOrder()
                    true
                }
                else -> true
            }
        }
    }

    /**
     * كل ما تحرك الإصبع فوق llConfigList أثناء السحب، كنشوفو فين خاص
     * الصف المسحوب يتحرك (حسب منتصف كل صف آخر مقارنة بموقع الإصبع Y)،
     * وكنعاودو نرتبوه هناك مباشرة - هادشي كيعطي إحساس "حي" للترتيب
     * (بحال RecyclerView + ItemTouchHelper، لكن يدويا لأن llConfigList
     * هي LinearLayout عادية).
     */
    private fun handleDragLocation(y: Float) {
        val dragged = draggedRow ?: return
        val currentIndex = llConfigList.indexOfChild(dragged)
        if (currentIndex == -1) return
        var targetIndex = llConfigList.childCount - 1
        for (i in 0 until llConfigList.childCount) {
            val child = llConfigList.getChildAt(i)
            if (child == dragged) continue
            val mid = (child.top + child.bottom) / 2f
            if (y < mid) {
                targetIndex = i
                break
            }
        }
        if (targetIndex != currentIndex) {
            llConfigList.removeView(dragged)
            val adjusted = if (targetIndex > currentIndex) targetIndex - 1 else targetIndex
            llConfigList.addView(dragged, adjusted.coerceIn(0, llConfigList.childCount))
        }
    }

    private fun configOrderPrefs() = requireContext().getSharedPreferences("config_order_prefs", 0)

    /** كيسجل الترتيب البصري الحالي ديال llConfigList (لائحة الأسماء بالترتيب) - كيتقرا مرة أخرى فـapplySavedOrder(). */
    private fun persistCurrentOrder() {
        val nameByView = rowViews.entries.associate { (name, view) -> view to name }
        val names = (0 until llConfigList.childCount).mapNotNull { i -> nameByView[llConfigList.getChildAt(i)] }
        if (names.isEmpty()) return
        val arr = JSONArray(names)
        configOrderPrefs().edit().putString("order", arr.toString()).apply()
    }

    private fun loadSavedOrder(): List<String> {
        val raw = configOrderPrefs().getString("order", null) ?: return emptyList()
        return try {
            val arr = JSONArray(raw)
            (0 until arr.length()).map { arr.getString(it) }
        } catch (_: Throwable) {
            emptyList()
        }
    }

    /**
     * كيرتب entries حسب آخر ترتيب سجله المستخدم بيدو (Drag & Drop) - أي
     * ملف جديد ماكاينش بعد فالترتيب المسجل (تزاد من بعد آخر مرة رتب فيها
     * المستخدم) كيبان فالأعلى، بنفس ترتيب "الأحدث فوق" الافتراضي القديم
     * ديال ConfigStorageManager.list().
     */
    private fun applySavedOrder(entries: List<ConfigFileEntry>): List<ConfigFileEntry> {
        val savedOrder = loadSavedOrder()
        if (savedOrder.isEmpty()) return entries
        val byName = entries.associateBy { it.displayName }
        val known = savedOrder.mapNotNull { byName[it] }
        val knownNames = known.map { it.displayName }.toSet()
        val unknown = entries.filter { it.displayName !in knownNames }
        return unknown + known
    }

    // ===== زر ★/■: بدء/وقف الاتصال بهاد الكونفيغ بالضبط، بلا مغادرة CONFIG tab =====

    private fun onActionTapped(entry: ConfigFileEntry) {
        val ctx = context ?: return
        val activity = requireActivity() as? MainActivity ?: return

        // FIX: كان ناقص isReconnectingNow() هنا - فملي الملف كيدخل
        // RECONNECTING (connected=false, connecting=false,
        // reconnectingUi=true) بعد قطع شبكة، هاد الشرط كان كيرجع false،
        // فالضغط على زر التوقف (⏹) ماكانش كيوقف الملف، بل كيكمل للكود
        // تحت اللي كيبدا محاولة CONNECT جديدة - وهادشي هو اللي كان
        // كيبين كـ"Connecting..." بدل التوقف، وكان محتاج ضغطة ثانية.
        if (activity.isConfigFileActive(entry.displayName) &&
            (activity.isConnectedNow() || activity.isConnectingNow() || activity.isReconnectingNow())
        ) {
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
            .create()
            .apply { setCanceledOnTouchOutside(false) }
            .show()
    }

    // ===== لوحة موسعة: Edit / Share / Delete (Edit غير للملفات بلا كلمة سر) =====

    private fun editEntry(entry: ConfigFileEntry) {
        val ctx = context ?: return
        // لا نعتمد على cache هنا، لأن صلاحية Edit خاصها تتأكد من الملف
        // نفسه + التوقيع + Android Keystore ديال هذا الجهاز.
        lifecycleScope.launch {
            val bytes = withContext(Dispatchers.IO) { ConfigStorageManager.readBytes(ctx, entry.uri) }
            if (bytes == null) {
                Toast.makeText(ctx, "Could not read file.", Toast.LENGTH_SHORT).show()
                return@launch
            }

            if (entry.isEncrypted) {
                promptPasswordForEdit(entry, bytes)
            } else {
                try {
                    val parsed = withContext(Dispatchers.Default) { MlConfigFile.parse(bytes, null) }
                    if (!MlConfigFile.isOwner(ctx, parsed)) {
                        Toast.makeText(ctx, "Only the device that created this config can edit it.", Toast.LENGTH_LONG).show()
                        return@launch
                    }
                    (requireActivity() as? MainActivity)?.loadFieldsForEditing(
                        entry.displayName, parsed.fields, ownerVerified = true
                    )
                    Toast.makeText(ctx, "Loaded into SSH SETTINGS for editing. Use + NEW CONFIG to save your changes.", Toast.LENGTH_LONG).show()
                } catch (_: Throwable) {
                    Toast.makeText(ctx, "Could not verify config ownership.", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    /** Password كتفتح المحتوى، ولكن الملكية كتتحقق بالتوقيع + Android Keystore. */
    private fun promptPasswordForEdit(entry: ConfigFileEntry, bytes: ByteArray) {
        val ctx = context ?: return
        val input = EditText(ctx).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = "Password"
        }
        AlertDialog.Builder(ctx)
            .setTitle("Protected Config")
            .setMessage("Enter the password. Editing is allowed only on the device that created this config.")
            .setView(wrapDialogInput(input))
            .setPositiveButton("Continue") { _, _ ->
                val password = input.text.toString()
                lifecycleScope.launch {
                    try {
                        val parsed = withContext(Dispatchers.Default) { MlConfigFile.parse(bytes, password) }
                        if (!MlConfigFile.isOwner(ctx, parsed)) {
                            Toast.makeText(ctx, "This config belongs to another device. You can connect to it, but you cannot edit it.", Toast.LENGTH_LONG).show()
                            return@launch
                        }
                        UnlockedConfigCache.put(entry.displayName, parsed.fields)
                        (requireActivity() as? MainActivity)?.loadFieldsForEditing(
                            entry.displayName, parsed.fields, ownerVerified = true
                        )
                        Toast.makeText(ctx, "Loaded into SSH SETTINGS for editing. Use + NEW CONFIG to save your changes.", Toast.LENGTH_LONG).show()
                    } catch (_: MlConfigParseException) {
                        Toast.makeText(ctx, "Wrong password or invalid config.", Toast.LENGTH_SHORT).show()
                    } catch (_: Throwable) {
                        Toast.makeText(ctx, "Could not verify config ownership.", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .create()
            .apply { setCanceledOnTouchOutside(false) }
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
