package net.kaaass.zerotierfix.util;

import android.util.Log;

import androidx.core.view.MotionEventCompat;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

public class IPPacketUtils {
    private static final String TAG = "IPPacketUtils";

    public static InetAddress getSourceIP(byte[] bArr) {
        byte iPVersion = getIPVersion(bArr);
        if (iPVersion == 4) {
            byte[] bArr2 = new byte[4];
            System.arraycopy(bArr, 12, bArr2, 0, 4);
            try {
                return InetAddress.getByAddress(bArr2);
            } catch (UnknownHostException e) {
                Log.e(TAG, "Error creating InetAddress: " + e.getMessage(), e);
                return null;
            }
        } else if (iPVersion == 6) {
            byte[] bArr3 = new byte[16];
            System.arraycopy(bArr, 8, bArr3, 0, 16);
            try {
                return InetAddress.getByAddress(bArr3);
            } catch (UnknownHostException e) {
                Log.e(TAG, "Error creating InetAddress: " + e.getMessage(), e);
                return null;
            }
        } else {
            Log.e(TAG, "Unknown IP version");
            return null;
        }
    }

    public static InetAddress getSourceIP(ByteBuffer buffer) {
        buffer.mark();
        int currPos = buffer.position();
        try {
            byte iPVersion = getIPVersion(buffer);
            if (iPVersion == 4) {
                buffer.position(currPos + 12);
                byte[] bArr2 = new byte[4];
                buffer.get(bArr2);
                try {
                    return InetAddress.getByAddress(bArr2);
                } catch (UnknownHostException e) {
                    Log.e(TAG, "Error creating InetAddress: " + e.getMessage(), e);
                    return null;
                }
            } else if (iPVersion == 6) {
                buffer.position(currPos + 8);
                byte[] bArr3 = new byte[16];
                buffer.get(bArr3);
                try {
                    return InetAddress.getByAddress(bArr3);
                } catch (UnknownHostException e) {
                    Log.e(TAG, "Error creating InetAddress: " + e.getMessage(), e);
                    return null;
                }
            } else {
                Log.e(TAG, "Unknown IP version");
                return null;
            }
        } finally {
            buffer.reset();
        }
    }

    public static InetAddress getDestIP(ByteBuffer buffer) {
        buffer.mark();
        int currPos = buffer.position();
        try {
            byte iPVersion = getIPVersion(buffer);
            if (iPVersion == 4) {
                buffer.position(currPos + 16);
                byte[] bArr2 = new byte[4];
                buffer.get(bArr2);
                try {
                    return InetAddress.getByAddress(bArr2);
                } catch (UnknownHostException e) {
                    Log.e(TAG, "Error creating InetAddress: " + e.getMessage(), e);
                    return null;
                }
            } else if (iPVersion == 6) {
                buffer.position(currPos + 24);
                byte[] bArr3 = new byte[16];
                buffer.get(bArr3);
                try {
                    return InetAddress.getByAddress(bArr3);
                } catch (UnknownHostException e) {
                    Log.e(TAG, "Error creating InetAddress: " + e.getMessage(), e);
                    return null;
                }
            } else {
                Log.e(TAG, "Unknown IP version");
                return null;
            }
        } finally {
            buffer.reset();
        }
    }

    public static byte getIPVersion(byte[] bArr) {
        return (byte) (bArr[0] >> 4);
    }

    public static byte getIPVersion(ByteBuffer buffer) {
        buffer.mark();
        byte ret = (byte) (buffer.get() >> 4);
        buffer.reset();
        return ret;
    }

    public static long calculateChecksum(byte[] bArr, long j, int i, int i2) {
        int i3 = i2 - i;
        while (i3 > 1) {
            j += (long) ((65280 & (bArr[i] << 8)) | (bArr[i + 1] & 255));
            if ((-65536 & j) > 0) {
                j = (j & 65535) + 1;
            }
            i += 2;
            i3 -= 2;
        }
        if (i3 > 0) {
            j += (long) ((bArr[i] << 8) & MotionEventCompat.ACTION_POINTER_INDEX_MASK);
            if ((j & -65536) > 0) {
                j = (j & 65535) + 1;
            }
        }
        return (~j) & 65535;
    }
}
