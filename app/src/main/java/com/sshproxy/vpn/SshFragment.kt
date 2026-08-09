package com.sshproxy.vpn

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.fragment.app.Fragment

/**
 * تبويب SSH: الحقول اليدوية + أزرار Connect/Share Log/Import.
 * الفراگمنت هادي "غبية" عمدا — ماعندهاش أي منطق اتصال، غير كتسجل
 * الـ views ديالها عند MainActivity (اللي فيه كل منطق الاتصال والـ
 * service)، باش نتجنبو تكرار/تعارض الحالة بين مكانين.
 */
class SshFragment : Fragment(R.layout.fragment_ssh) {

    lateinit var edtHost: EditText
    lateinit var edtUser: EditText
    lateinit var edtPass: EditText
    lateinit var edtPayload: EditText
    lateinit var edtProxy: EditText
    lateinit var chkUsePayload: CheckBox
    lateinit var chkUseSsl: CheckBox
    lateinit var edtSni: EditText
    lateinit var chkUdpgw: CheckBox
    lateinit var edtUdpgwPort: EditText
    lateinit var manualFieldsContainer: LinearLayout
    lateinit var btnConnect: Button
    lateinit var btnShareLog: Button
    lateinit var btnImportConfig: Button
    lateinit var btnRemoveImported: Button
    lateinit var importedStatusContainer: LinearLayout
    lateinit var txtImportedStatus: TextView

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        edtHost = view.findViewById(R.id.edtHost)
        edtUser = view.findViewById(R.id.edtUser)
        edtPass = view.findViewById(R.id.edtPass)
        edtPayload = view.findViewById(R.id.edtPayload)
        edtProxy = view.findViewById(R.id.edtProxy)
        chkUsePayload = view.findViewById(R.id.chkUsePayload)
        chkUseSsl = view.findViewById(R.id.chkUseSsl)
        edtSni = view.findViewById(R.id.edtSni)
        chkUdpgw = view.findViewById(R.id.chkUdpgw)
        edtUdpgwPort = view.findViewById(R.id.edtUdpgwPort)
        manualFieldsContainer = view.findViewById(R.id.manualFieldsContainer)
        btnConnect = view.findViewById(R.id.btnConnect)
        btnShareLog = view.findViewById(R.id.btnShareLog)
        btnImportConfig = view.findViewById(R.id.btnImportConfig)
        btnRemoveImported = view.findViewById(R.id.btnRemoveImported)
        importedStatusContainer = view.findViewById(R.id.importedStatusContainer)
        txtImportedStatus = view.findViewById(R.id.txtImportedStatus)

        (requireActivity() as? MainActivity)?.onSshFragmentReady(this)
    }
}
