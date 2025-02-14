package net.kaaass.zerotierfix.service;

import android.util.Log;

import net.kaaass.zerotierfix.util.IPPacketUtils;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.HashMap;

// TODO: clear up
public class NDPTable {
    public static final String TAG = "NDPTable";
    private static final long ENTRY_TIMEOUT = 120000;
    private final HashMap<Long, NDPEntry> entriesMap = new HashMap<>();
    private final HashMap<InetAddress, Long> inetAddressToMacAddress = new HashMap<>();
    private final HashMap<InetAddress, NDPEntry> ipEntriesMap = new HashMap<>();
    private final HashMap<Long, InetAddress> macAddressToInetAddress = new HashMap<>();
    private final Thread timeoutThread = new Thread("NDP Timeout Thread") {
        /* class com.zerotier.one.service.NDPTable.AnonymousClass1 */

        @Override
        public void run() {
            while (!isInterrupted()) {
                try {
                    for (NDPEntry nDPEntry : new HashMap<>(NDPTable.this.entriesMap).values()) {
                        if (nDPEntry.getTime() + NDPTable.ENTRY_TIMEOUT < System.currentTimeMillis()) {
                            synchronized (NDPTable.this.macAddressToInetAddress) {
                                NDPTable.this.macAddressToInetAddress.remove(Long.valueOf(nDPEntry.getMac()));
                            }
                            synchronized (NDPTable.this.inetAddressToMacAddress) {
                                NDPTable.this.inetAddressToMacAddress.remove(nDPEntry.getAddress());
                            }
                            synchronized (NDPTable.this.entriesMap) {
                                NDPTable.this.entriesMap.remove(Long.valueOf(nDPEntry.getMac()));
                            }
                            synchronized (NDPTable.this.ipEntriesMap) {
                                NDPTable.this.ipEntriesMap.remove(nDPEntry.getAddress());
                            }
                        }
                    }
                    Thread.sleep(1000);
                } catch (Exception e) {
                    Log.d(NDPTable.TAG, e.toString());
                    return;
                }
            }
        }
    };

    public NDPTable() {
        this.timeoutThread.start();
    }

    /* access modifiers changed from: protected */
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
        synchronized (this.macAddressToInetAddress) {
            this.macAddressToInetAddress.put(Long.valueOf(j), inetAddress);
        }
        NDPEntry nDPEntry = new NDPEntry(j, inetAddress);
        synchronized (this.entriesMap) {
            this.entriesMap.put(Long.valueOf(j), nDPEntry);
        }
        synchronized (this.ipEntriesMap) {
            this.ipEntriesMap.put(inetAddress, nDPEntry);
        }
    }

    /* access modifiers changed from: package-private */
    public boolean hasMacForAddress(InetAddress inetAddress) {
        boolean containsKey;
        synchronized (this.inetAddressToMacAddress) {
            containsKey = this.inetAddressToMacAddress.containsKey(inetAddress);
        }
        return containsKey;
    }

    /* access modifiers changed from: package-private */
    public boolean hasAddressForMac(long j) {
        boolean containsKey;
        synchronized (this.macAddressToInetAddress) {
            containsKey = this.macAddressToInetAddress.containsKey(Long.valueOf(j));
        }
        return containsKey;
    }

    /* access modifiers changed from: package-private */
    public long getMacForAddress(InetAddress inetAddress) {
        synchronized (this.inetAddressToMacAddress) {
            if (!this.inetAddressToMacAddress.containsKey(inetAddress)) {
                return -1;
            }
            long longValue = this.inetAddressToMacAddress.get(inetAddress).longValue();
            updateNDPEntryTime(longValue);
            return longValue;
        }
    }

    /* access modifiers changed from: package-private */
    public InetAddress getAddressForMac(long j) {
        synchronized (this.macAddressToInetAddress) {
            if (!this.macAddressToInetAddress.containsKey(Long.valueOf(j))) {
                return null;
            }
            InetAddress inetAddress = this.macAddressToInetAddress.get(Long.valueOf(j));
            updateNDPEntryTime(inetAddress);
            return inetAddress;
        }
    }

    private void updateNDPEntryTime(InetAddress inetAddress) {
        synchronized (this.ipEntriesMap) {
            NDPEntry nDPEntry = this.ipEntriesMap.get(inetAddress);
            if (nDPEntry != null) {
                nDPEntry.updateTime();
            }
        }
    }

    private void updateNDPEntryTime(long j) {
        synchronized (this.entriesMap) {
            NDPEntry nDPEntry = this.entriesMap.get(Long.valueOf(j));
            if (nDPEntry != null) {
                nDPEntry.updateTime();
            }
        }
    }

    /* access modifiers changed from: package-private */
    public ByteBuffer getNeighborSolicitationPacket(InetAddress inetAddress, InetAddress inetAddress2, long j) {
        ByteBuffer buffer = ByteBuffer.allocateDirect(72);
        buffer.put(inetAddress.getAddress(), 0, 16);
        buffer.put(inetAddress2.getAddress(), 0, 16);
        // Put 32 as an int (4 bytes)
        buffer.putInt(32);
        // Put 58 and -121 (2 bytes)
        buffer.put((byte) 58);
        buffer.put((byte) -121);
        // Copy inetAddress2 again (16 bytes)
        buffer.put(inetAddress2.getAddress(), 0, 16);
        // Put j as a long (8 bytes)
        ByteBuffer longBuffer = ByteBuffer.allocate(8).putLong(j);
        longBuffer.flip(); // Prepare for reading
        longBuffer.position(2); // Skip the first 2 bytes
        buffer.put((byte) 1);
        buffer.put((byte) 1);
        buffer.put(longBuffer);
        // Calculate and put checksum (2 bytes)
        short checksum = (short) IPPacketUtils.calculateChecksum(buffer.array(), 0, 0, 72);
        buffer.position(42);
        buffer.putShort(checksum);
        // Reset position for the next part
        buffer.position(0);
        // Fill the first 40 bytes with 0
        for (int i = 0; i < 40; i++) {
            buffer.put((byte) 0);
        }
        // Set the first byte to 96
        buffer.put(0, (byte) 96);
        // Put 32 as a short (2 bytes) at position 4
        buffer.putShort(4, (short) 32);
        // Put 58 and -1 at positions 6 and 7
        buffer.put(6, (byte) 58);
        buffer.put(7, (byte) -1);
        // Copy inetAddress (16 bytes) at position 8
        buffer.position(8);
        buffer.put(inetAddress.getAddress());
        // Copy inetAddress2 (16 bytes) at position 24
        buffer.position(24);
        buffer.put(inetAddress2.getAddress());
        buffer.rewind();
        return buffer;
    }

}
