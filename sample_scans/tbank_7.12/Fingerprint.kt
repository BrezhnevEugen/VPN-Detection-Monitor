package demo

object Fingerprint {
    fun read(): String {
        val marker = "isVpnConnected"
        val port = "proc/net/tcp:27042"
        val iface = "tun0"
        return "$marker:$port:$iface"
    }
}
