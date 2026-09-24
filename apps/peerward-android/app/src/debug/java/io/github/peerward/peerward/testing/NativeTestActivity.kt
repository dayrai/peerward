package io.github.peerward.peerward.testing

import android.app.Activity
import android.os.Bundle
import android.widget.TextView
import io.github.peerward.peerward.R

/** Foreground owner for synthetic native tests; never packaged in a release. */
class NativeTestActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply { setText(R.string.native_test_controller) })
    }
}
