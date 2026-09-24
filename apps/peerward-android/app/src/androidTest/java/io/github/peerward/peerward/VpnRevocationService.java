package io.github.peerward.peerward;

import android.content.Intent;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import java.io.IOException;

/** Separate test VPN owns only a documentation /32; bounded lifetime and no normal routes. */
public class VpnRevocationService extends VpnService {
    private ParcelFileDescriptor tun;
    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (tun == null) tun = new Builder().setSession("Peerward revocation validation")
            .addAddress("192.0.2.1", 32).addRoute("192.0.2.1", 32).establish();
        new Handler(Looper.getMainLooper()).postDelayed(this::stopSelf, 20_000);
        return START_NOT_STICKY;
    }
    @Override public void onDestroy() {
        if (tun != null) { try { tun.close(); } catch (IOException ignored) { } tun = null; }
        super.onDestroy();
    }
}
