package com.sshproxy.vpn

import android.content.ContentValues
import android.content.Context
import android.media.MediaScannerConnection
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import androidx.core.content.FileProvider
import com.sshproxy.vpn.importer.MlConfigFile
import java.io.File

data class ConfigFileEntry(
    val uri: Uri,
    val displayName: String,
    val isEncrypted: Boolean
)

/**
 * كيخزن/كيقرا/كيمسح ملفات .ml فـ Downloads/MR VPN TUNNEL - عبر MediaStore
 * (Scoped Storage) فـ Android 10+، وعبر File مباشرة (+ FileProvider للمشاركة)
 * فـ Android القديم. بلا ما نمس أي حاجة أخرى فالمشروع.
 */
object ConfigStorageManager {

    private const val SUBFOLDER = "MR VPN TUNNEL"
    private const val MIME_TYPE = "application/octet-stream"

    private fun sanitizeFileName(raw: String): String {
        // كنسمحو بأي رمز/إيموجي (بحال ما طلب المستخدم) - غير كنشيلو
        // الرموز لي ممنوعة فأسماء الملفات فـ Android (/ \ : * ? " < > |).
        val cleaned = raw.trim().replace(Regex("""[/\\:*?"<>|]"""), "_")
        return cleaned.ifBlank { "config_${System.currentTimeMillis()}" }
    }

    fun finalFileName(rawName: String): String {
        val safe = sanitizeFileName(rawName)
        return if (safe.endsWith(".${MlConfigFile.EXTENSION}", ignoreCase = true)) safe
        else "$safe.${MlConfigFile.EXTENSION}"
    }

    fun save(context: Context, rawName: String, bytes: ByteArray): Uri? {
        val fileName = finalFileName(rawName)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            saveViaMediaStore(context, fileName, bytes)
        } else {
            saveLegacy(context, fileName, bytes)
        }
    }

    private fun saveViaMediaStore(context: Context, fileName: String, bytes: ByteArray): Uri? {
        val resolver = context.contentResolver
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, fileName)
            put(MediaStore.Downloads.MIME_TYPE, MIME_TYPE)
            put(MediaStore.Downloads.RELATIVE_PATH, "${Environment.DIRECTORY_DOWNLOADS}/$SUBFOLDER")
            put(MediaStore.Downloads.IS_PENDING, 1)
        }
        val collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI
        val uri = resolver.insert(collection, values) ?: return null
        try {
            resolver.openOutputStream(uri)?.use { it.write(bytes) } ?: return null
        } catch (_: Throwable) {
            resolver.delete(uri, null, null)
            return null
        }
        values.clear()
        values.put(MediaStore.Downloads.IS_PENDING, 0)
        resolver.update(uri, values, null, null)
        return uri
    }

    private fun downloadsDir(): File =
        File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), SUBFOLDER)

    private fun saveLegacy(context: Context, fileName: String, bytes: ByteArray): Uri? {
        return try {
            val dir = downloadsDir()
            if (!dir.exists()) dir.mkdirs()
            val file = File(dir, fileName)
            file.writeBytes(bytes)
            MediaScannerConnection.scanFile(context, arrayOf(file.absolutePath), null, null)
            FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        } catch (_: Throwable) {
            null
        }
    }

    /** كيبدل محتوى ملف موجود (Edit) - غير للملفات بلا كلمة سر منطقيا، لكن التقني هنا ماكيفرقش. */
    fun overwrite(context: Context, entry: ConfigFileEntry, bytes: ByteArray): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && entry.uri.authority == MediaStore.AUTHORITY) {
                context.contentResolver.openOutputStream(entry.uri, "wt")?.use { it.write(bytes) } != null
            } else {
                val file = legacyFileFor(context, entry.uri) ?: return false
                file.writeBytes(bytes)
                MediaScannerConnection.scanFile(context, arrayOf(file.absolutePath), null, null)
                true
            }
        } catch (_: Throwable) {
            false
        }
    }

    fun delete(context: Context, entry: ConfigFileEntry): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && entry.uri.authority == MediaStore.AUTHORITY) {
                context.contentResolver.delete(entry.uri, null, null) > 0
            } else {
                val file = legacyFileFor(context, entry.uri) ?: return false
                file.delete()
            }
        } catch (_: Throwable) {
            false
        }
    }

    fun readBytes(context: Context, uri: Uri): ByteArray? {
        return try {
            context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
        } catch (_: Throwable) {
            null
        }
    }

    /** لائحة كل ملفات .ml فـ Downloads/MR VPN TUNNEL - مرتبة الأحدث أولا. */
    fun list(context: Context): List<ConfigFileEntry> {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            listViaMediaStore(context)
        } else {
            listLegacy(context)
        }
    }

    private fun listViaMediaStore(context: Context): List<ConfigFileEntry> {
        val result = mutableListOf<ConfigFileEntry>()
        val collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI
        val projection = arrayOf(MediaStore._ID, MediaStore.Downloads.DISPLAY_NAME, MediaStore.Downloads.RELATIVE_PATH)
        val selection = "${MediaStore.Downloads.RELATIVE_PATH} = ? AND ${MediaStore.Downloads.DISPLAY_NAME} LIKE ?"
        val args = arrayOf("${Environment.DIRECTORY_DOWNLOADS}/$SUBFOLDER/", "%.${MlConfigFile.EXTENSION}")
        try {
            context.contentResolver.query(collection, projection, selection, args, "${MediaStore.Downloads.DATE_ADDED} DESC")?.use { c ->
                val idCol = c.getColumnIndexOrThrow(MediaStore._ID)
                val nameCol = c.getColumnIndexOrThrow(MediaStore.Downloads.DISPLAY_NAME)
                while (c.moveToNext()) {
                    val id = c.getLong(idCol)
                    val name = c.getString(nameCol)
                    val uri = Uri.withAppendedPath(collection, id.toString())
                    val encrypted = try {
                        readBytes(context, uri)?.let { MlConfigFile.isEncrypted(it) } ?: false
                    } catch (_: Throwable) { false }
                    result.add(ConfigFileEntry(uri, name, encrypted))
                }
            }
        } catch (_: Throwable) { }
        return result
    }

    private fun listLegacy(context: Context): List<ConfigFileEntry> {
        val dir = downloadsDir()
        if (!dir.exists()) return emptyList()
        val files = dir.listFiles { f -> f.isFile && f.name.endsWith(".${MlConfigFile.EXTENSION}", ignoreCase = true) }
            ?.sortedByDescending { it.lastModified() } ?: return emptyList()
        return files.map { f ->
            val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", f)
            val encrypted = try {
                f.readBytes().let { MlConfigFile.isEncrypted(it) }
            } catch (_: Throwable) { false }
            ConfigFileEntry(uri, f.name, encrypted)
        }
    }

    private fun legacyFileFor(context: Context, uri: Uri): File? {
        // الملفات القديمة كلهم عبر FileProvider بنفس authority - كنرجعو
        // للـFile الأصلي بحث بالاسم فنفس المجلد (FileProvider ماعندهاش
        // getFile عكسي مباشر).
        val dir = downloadsDir()
        val name = uri.lastPathSegment?.substringAfterLast('/') ?: return null
        val candidate = File(dir, name)
        return if (candidate.exists()) candidate else null
    }
}

