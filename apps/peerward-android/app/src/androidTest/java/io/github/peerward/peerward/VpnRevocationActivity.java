package io.github.peerward.peerward;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;

/** Standalone test APK process: platform-only Java; the target owns Kotlin dependencies. */
public class VpnRevocationActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        if ("peerward.test.STOP_VPN".equals(getIntent().getAction())) {
            stopService(new Intent(this, VpnRevocationService.class));
            finish();
            return;
        }
        Intent permission = VpnService.prepare(this);
        if (permission == null) startProbe(); else startActivityForResult(permission, 1);
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == 1 && result == RESULT_OK) startProbe(); else finish();
    }
    private void startProbe() {
        startService(new Intent(this, VpnRevocationService.class));
        // Return to the product Activity for verification. Keeping the test APK
        // in front can freeze the target instrumentation process on physical OEMs.
        finish();
    }
}
