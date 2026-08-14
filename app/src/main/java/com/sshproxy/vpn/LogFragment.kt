package com.sshproxy.vpn

import android.os.Bundle
import android.view.View
import android.widget.ScrollView
import android.widget.TextView
import androidx.fragment.app.Fragment

/** تبويب LOG: غير TextView + ScrollView، بلا أي منطق. */
class LogFragment : Fragment(R.layout.fragment_log) {

    lateinit var txtLog: TextView
    lateinit var logScroll: ScrollView

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        txtLog = view.findViewById(R.id.txtLog)
        logScroll = view.findViewById(R.id.logScroll)

        (requireActivity() as? MainActivity)?.onLogFragmentReady(this)
    }
}

