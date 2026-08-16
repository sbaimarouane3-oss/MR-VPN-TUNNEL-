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
    lateinit var sniSection: LinearLayout
    lateinit var payloadSection: LinearLayout
    lateinit var proxySection: LinearLayout
    lateinit var sshCoreFieldsSection: LinearLayout
    lateinit var udpgwSection: LinearLayout
    lateinit var v2raySection: LinearLayout
    lateinit var edtV2rayJson: EditText
    lateinit var shadowsocksSection: LinearLayout
    lateinit var edtSsServer: EditText
    lateinit var edtSsPort: EditText
    lateinit var edtSsMethod: EditText
    lateinit var edtSsPassword: EditText
    lateinit var chkSsUdp: CheckBox
    lateinit var btnConnect: Button
    lateinit var btnShareLog: Button
    lateinit var btnImportConfig: Button
    lateinit var btnRemoveImported: Button
    lateinit var importedStatusContainer: LinearLayout
    lateinit var txtImportedStatus: TextView
    lateinit var btnNewConfig: Button

    // Views ديال التصميم الجديد فقط (عرض/status) — بلا أي منطق اتصال،
    // كيتحدثو فـ MainActivity جنب نفس الأسطر لي كانت كتبدل نص btnConnect
    // من قبل.
    lateinit var viewConnectPulseRing: View
    lateinit var txtServerValue: TextView
    lateinit var txtProtocolValue: TextView
    lateinit var rowProtocol: View
    lateinit var txtPortValue: TextView
    lateinit var txtStatusCardValue: TextView

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
        sniSection = view.findViewById(R.id.sniSection)
        payloadSection = view.findViewById(R.id.payloadSection)
        proxySection = view.findViewById(R.id.proxySection)
        sshCoreFieldsSection = view.findViewById(R.id.sshCoreFieldsSection)
        udpgwSection = view.findViewById(R.id.udpgwSection)
        v2raySection = view.findViewById(R.id.v2raySection)
        edtV2rayJson = view.findViewById(R.id.edtV2rayJson)
        shadowsocksSection = view.findViewById(R.id.shadowsocksSection)
        edtSsServer = view.findViewById(R.id.edtSsServer)
        edtSsPort = view.findViewById(R.id.edtSsPort)
        edtSsMethod = view.findViewById(R.id.edtSsMethod)
        edtSsPassword = view.findViewById(R.id.edtSsPassword)
        chkSsUdp = view.findViewById(R.id.chkSsUdp)
        btnConnect = view.findViewById(R.id.btnConnect)
        btnShareLog = view.findViewById(R.id.btnShareLog)
        btnImportConfig = view.findViewById(R.id.btnImportConfig)
        btnRemoveImported = view.findViewById(R.id.btnRemoveImported)
        importedStatusContainer = view.findViewById(R.id.importedStatusContainer)
        txtImportedStatus = view.findViewById(R.id.txtImportedStatus)
        btnNewConfig = view.findViewById(R.id.btnNewConfig)

        viewConnectPulseRing = view.findViewById(R.id.viewConnectPulseRing)
        txtServerValue = view.findViewById(R.id.txtServerValue)
        txtProtocolValue = view.findViewById(R.id.txtProtocolValue)
        rowProtocol = view.findViewById(R.id.rowProtocol)
        txtPortValue = view.findViewById(R.id.txtPortValue)
        txtStatusCardValue = view.findViewById(R.id.txtStatusCardValue)

        (requireActivity() as? MainActivity)?.onSshFragmentReady(this)
    }
}
