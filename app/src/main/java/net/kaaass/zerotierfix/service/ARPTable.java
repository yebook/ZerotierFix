package net.kaaass.zerotierfix.service;

import android.util.Log;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.HashMap;

// TODO: clear up
public class ARPTable {
    public static final String TAG = "ARPTable";
    private static final long ENTRY_TIMEOUT = 120000;
    private static final int REPLY = 2;
    private static final int REQUEST = 1;
    private final HashMap<Long, ARPEntry> entriesMap = new HashMap<>();
    private final HashMap<InetAddress, Long> inetAddressToMacAddress = new HashMap<>();
    private final HashMap<InetAddress, ARPEntry> ipEntriesMap = new HashMap<>();
    private final HashMap<Long, InetAddress> macAddressToInetAdddress = new HashMap<>();
    private final Thread timeoutThread = new Thread("ARP Timeout Thread") {
        /* class com.zerotier.one.service.ARPTable.AnonymousClass1 */

        public void run() {
            while (!isInterrupted()) {
                try {
                    for (ARPEntry arpEntry : new HashMap<>(ARPTable.this.entriesMap).values()) {
                        if (arpEntry.getTime() + ARPTable.ENTRY_TIMEOUT < System.currentTimeMillis()) {
                            Log.d(ARPTable.TAG, "Removing " + arpEntry.getAddress().toString() + " from ARP cache");
                            synchronized (ARPTable.this.macAddressToInetAdddress) {
                                ARPTable.this.macAddressToInetAdddress.remove(Long.valueOf(arpEntry.getMac()));
                            }
                            synchronized (ARPTable.this.inetAddressToMacAddress) {
                                ARPTable.this.inetAddressToMacAddress.remove(arpEntry.getAddress());
                            }
                            synchronized (ARPTable.this.entriesMap) {
                                ARPTable.this.entriesMap.remove(Long.valueOf(arpEntry.getMac()));
                            }
                            synchronized (ARPTable.this.ipEntriesMap) {
                                ARPTable.this.ipEntriesMap.remove(arpEntry.getAddress());
                            }
                        }
                    }
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Log.e(ARPTable.TAG, "Tun/Tap Interrupted", e);
                    break;
                } catch (Exception e) {
                    Log.d(ARPTable.TAG, e.toString());
                }
            }
            Log.d(ARPTable.TAG, "ARP Timeout Thread Ended.");
        }
    };

    public ARPTable() {
        this.timeoutThread.start();
    }

    public static byte[] longToBytes(long j) {
        ByteBuffer allocate = ByteBuffer.allocate(8);
        allocate.putLong(j);
        return allocate.array();
    }

    public void stop() {
        try {
            this.timeoutThread.interrupt();
            this.timeoutThread.join();
        } catch (InterruptedException ignored) {
        }
    }

    /* access modifiers changed from: package-private */
    public void setAddress(InetAddress inetAddress, long j) {
        synchronized (this.inetAddressToMacAddress) {
            this.inetAddressToMacAddress.put(inetAddress, Long.valueOf(j));
        }
        synchronized (this.macAddressToInetAdddress) {
            this.macAddressToInetAdddress.put(Long.valueOf(j), inetAddress);
        }
        ARPEntry arpEntry = new ARPEntry(j, inetAddress);
        synchronized (this.entriesMap) {
            this.entriesMap.put(j, arpEntry);
        }
        synchronized (this.ipEntriesMap) {
            this.ipEntriesMap.put(inetAddress, arpEntry);
        }
    }

    private void updateArpEntryTime(long j) {
        synchronized (this.entriesMap) {
            ARPEntry arpEntry = this.entriesMap.get(Long.valueOf(j));
            if (arpEntry != null) {
                arpEntry.updateTime();
            }
        }
    }

    private void updateArpEntryTime(InetAddress inetAddress) {
        synchronized (this.ipEntriesMap) {
            ARPEntry arpEntry = this.ipEntriesMap.get(inetAddress);
            if (arpEntry != null) {
                arpEntry.updateTime();
            }
        }
    }

    /* access modifiers changed from: package-private */
    public long getMacForAddress(InetAddress inetAddress) {
        synchronized (this.inetAddressToMacAddress) {
            if (!this.inetAddressToMacAddress.containsKey(inetAddress)) {
                return -1;
            }
            Log.d(TAG, "Returning MAC for " + inetAddress.toString());
            var longValue = this.inetAddressToMacAddress.get(inetAddress);
            if (longValue != null) {
                updateArpEntryTime(longValue);
                return longValue;
            }
        }
        return -1;
    }

    /* access modifiers changed from: package-private */
    public InetAddress getAddressForMac(long j) {
        synchronized (this.macAddressToInetAdddress) {
            if (!this.macAddressToInetAdddress.containsKey(Long.valueOf(j))) {
                return null;
            }
            InetAddress inetAddress = this.macAddressToInetAdddress.get(Long.valueOf(j));
            updateArpEntryTime(inetAddress);
            return inetAddress;
        }
    }

    public boolean hasMacForAddress(InetAddress inetAddress) {
        boolean containsKey;
        synchronized (this.inetAddressToMacAddress) {
            containsKey = this.inetAddressToMacAddress.containsKey(inetAddress);
        }
        return containsKey;
    }

    public boolean hasAddressForMac(long j) {
        boolean containsKey;
        synchronized (this.macAddressToInetAdddress) {
            containsKey = this.macAddressToInetAdddress.containsKey(Long.valueOf(j));
        }
        return containsKey;
    }

    public ByteBuffer getRequestPacket(long j, InetAddress inetAddress, InetAddress inetAddress2) {
        return getARPPacket(1, j, 0, inetAddress, inetAddress2);
    }

    public ByteBuffer getReplyPacket(long j, InetAddress inetAddress, long j2, InetAddress inetAddress2) {
        return getARPPacket(2, j, j2, inetAddress, inetAddress2);
    }

    public ByteBuffer getARPPacket(int operation, long senderMac, long targetMac, InetAddress senderIp, InetAddress targetIp) {
        ByteBuffer buffer = ByteBuffer.allocateDirect(28);

        // Hardware type (Ethernet)
        buffer.putShort((short) 0x0001); // 0,1

        // Protocol type (IPv4)
        buffer.putShort((short) 0x0800); // 2,3

        // Hardware size (MAC address length)
        buffer.put((byte) 0x06); // 4

        // Protocol size (IPv4 address length)
        buffer.put((byte) 0x04); // 5

        // Operation code
        buffer.putShort((short) operation); // 6,7

        // Sender MAC address
        byte[] senderMacBytes = longToBytes(senderMac);
        buffer.position(8);
        buffer.put(senderMacBytes, 2, 6); // 8-13

        // Sender IP address
        buffer.position(14);
        buffer.put(senderIp.getAddress()); // 14-17

        // Target MAC address
        byte[] targetMacBytes = longToBytes(targetMac);
        buffer.position(18);
        buffer.put(targetMacBytes, 2, 6); // 18-23

        // Target IP address
        buffer.position(24);
        buffer.put(targetIp.getAddress()); // 24-27

        buffer.rewind();
        return buffer;
    }

    public ARPReplyData processARPPacket(ByteBuffer packetData) {
        InetAddress srcAddress;
        InetAddress dstAddress;
        Log.d(TAG, "Processing ARP packet");
        int currPos = packetData.position();

        // 解析包内 IP、MAC 地址
        byte[] rawSrcMac = new byte[8];
        packetData.position(8);
        packetData.get(rawSrcMac, 2, 6);
        byte[] rawSrcAddress = new byte[4];
        packetData.position(14);
        packetData.get(rawSrcAddress, 0, 4);
        byte[] rawDstMac = new byte[8];
        packetData.position(18);
        packetData.get(rawDstMac, 2, 6);
        byte[] rawDstAddress = new byte[4];
        packetData.position(24);
        packetData.get(rawDstAddress, 0, 4);
        try {
            srcAddress = InetAddress.getByAddress(rawSrcAddress);
        } catch (Exception unused) {
            srcAddress = null;
        }
        try {
            dstAddress = InetAddress.getByAddress(rawDstAddress);
        } catch (Exception unused) {
            dstAddress = null;
        }
        long srcMac = ByteBuffer.wrap(rawSrcMac).getLong();
        long dstMac = ByteBuffer.wrap(rawDstMac).getLong();

        // 更新 ARP 表项
        if (srcMac != 0 && srcAddress != null) {
            setAddress(srcAddress, srcMac);
        }
        if (dstMac != 0 && dstAddress != null) {
            setAddress(dstAddress, dstMac);
        }

        // 处理响应行为
        packetData.position(7);
        var packetType = packetData.get();
        packetData.position(currPos);
        if (packetType == REQUEST) {
            // ARP 请求，返回应答数据
            Log.d(TAG, "Reply needed");
            return new ARPReplyData(srcMac, srcAddress);
        } else {
            return null;
        }
    }
}
