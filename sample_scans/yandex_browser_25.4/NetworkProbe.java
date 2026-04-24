package demo;

import android.net.NetworkCapabilities;

public final class NetworkProbe {
    public boolean detect(NetworkCapabilities caps) {
        boolean vpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
        String iface = "tun0";
        String proc = "/proc/net/tcp";
        String flag = "vpn_enabled";
        return vpn && iface != null && proc != null && flag != null;
    }
}
