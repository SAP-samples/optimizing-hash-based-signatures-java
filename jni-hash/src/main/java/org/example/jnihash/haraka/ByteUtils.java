package org.example.jnihash.haraka;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

public class ByteUtils {

    /**
     * Convert bytes to integer array, grouping 4 elements each
     *
     * @param buffer bytes needed to be grouped
     * @return grouped elements in big endian byte order
     */
    public static int[] convertToInt(byte[] buffer) {
        int length = buffer.length / 4;
        if (buffer.length % 4 != 0) {
            buffer = zeroLead(buffer.length + 4 - buffer.length % 4, buffer);
            length++;
        }
        int[] intArr = new int[length];
        for (int i = 0; i < intArr.length; i++) {
            intArr[i] = (buffer[3 + i * 4] & 0xFF) | ((buffer[2 + i * 4] & 0xFF) << 8) |
                    ((buffer[1 + i * 4] & 0xFF) << 16) | ((buffer[i * 4] & 0xFF) << 24);
        }
        return intArr;
    }

    /**
     * Convert bytes to integer array, grouping 4 elements each
     *
     * @param l long
     * @return grouped elements in big endian byte order
     */
    public static int[] convertToInt(long l) {
        int[] result = new int[2];
        for (int i = 1; i >= 0; i--) {
            result[i] = (int) (l & (-1) >> 32);
            l >>= 32;
        }
        return result;
    }

    /**
     * Convert bytes to integer array, grouping 4 elements each
     *
     * @param buffer bytes needed to be grouped
     * @return grouped elements in little endian byte order
     */
    public static int[] convertToLeInt(byte[] buffer) {
        int length = buffer.length / 4;
        if (buffer.length % 4 != 0) {
            buffer = zeroPad(buffer.length + 4 - buffer.length % 4, buffer);
            length++;
        }
        int[] intArr = new int[length];
        for (int i = 0; i < intArr.length; i++) {
            intArr[i] = (buffer[ i * 4] & 0xFF) | ((buffer[1 + i * 4] & 0xFF) << 8) |
                    ((buffer[2 + i * 4] & 0xFF) << 16) | ((buffer[3 + i * 4] & 0xFF) << 24);
        }
        return intArr;
    }

    /**
     * the constants need to be written in reverse order, as of program logic demands.
     *
     * @param buffer buffer in non-reverse order
     * @return constants in reverse order
     */
    public static int[] convertConstants(byte[] buffer) {
        int[] intArr = new int[buffer.length / 4];
        for (int i = 0; i < intArr.length; i++) {
            intArr[i ^ 3] = (buffer[3 + i * 4] & 0xFF) | ((buffer[2 + i * 4] & 0xFF) << 8) |
                    ((buffer[1 + i * 4] & 0xFF) << 16) | ((buffer[i * 4] & 0xFF) << 24);
        }

        return intArr;
    }


    /**
     * convert an integer array to a len long byte array
     *
     * @param nr  integer array
     * @param len length of returning array
     * @return len long byte array
     */
    public static byte[] convertToByte(int[] nr, int len) {
        byte[] result = new byte[4 * nr.length];
        byte[] fin = new byte[len];
        for (int i = 0; i < nr.length; i++) {
            result[i * 4] = (byte) (nr[i] >>> 24);
            result[i * 4 + 1] = (byte) (nr[i] >>> 16);
            result[i * 4 + 2] = (byte) (nr[i] >>> 8);
            result[i * 4 + 3] = (byte) nr[i];
        }
        System.arraycopy(result, 0, fin, 0, len);
        return fin;
    }

    /**
     * convert an integer to a len long byte array
     *
     * @param i   integer
     * @param len length of returning array
     * @return len long byte array
     */
    public static byte[] convertToByte(int i, int len) {
        byte[] result = new byte[4];
        result[0] = (byte) (i >>> 24);
        result[1] = (byte) (i >>> 16);
        result[2] = (byte) (i >>> 8);
        result[3] = (byte) i;
        byte[] fin = new byte[len];
        System.arraycopy(result, 0, fin, 0, len);
        return fin;
    }

    public static byte[] convertToByte(int[] nr) {
        byte[] result = new byte[4 * nr.length];
        for (int i = 0; i < nr.length; i++) {
            result[i * 4] = (byte) (nr[i] >>> 24);
            result[i * 4 + 1] = (byte) (nr[i] >>> 16);
            result[i * 4 + 2] = (byte) (nr[i] >>> 8);
            result[i * 4 + 3] = (byte) nr[i];
        }
        return result;
    }

    public static byte[] convertToByte(int i) {
        byte[] result = new byte[4];
        result[0] = (byte) (i >>> 24);
        result[1] = (byte) (i >>> 16);
        result[2] = (byte) (i >>> 8);
        result[3] = (byte) i;
        return result;
    }

    /**
     * convert integer to byte without leading 0's
     *
     * @param i integer to be converted
     * @return byte array without 0's
     */
    public static byte[] convertToNonZeroByte(int i) {
        byte[] result = new byte[4];
        byte tmp;
        int j = 0;
        for (int k = 3; k >= 0; k--) {
            tmp = (byte) (i >>> 8 * k);
            if (tmp != 0) {
                result[j] = tmp;
                j++;
            }
        }
        return result;
    }

    public static int[] padInt(int len) {
        return new int[len];
    }

    public static byte[] padByte(int len) {
        return new byte[len];
    }

    /**
     * pad the string to the next 32-bit value
     *
     * @param unpadded unpadded byte array
     * @return padded byte array
     */
    public static byte[] shakePad(byte[] unpadded) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(unpadded, 0, unpadded.length);
        int offset = 32 - unpadded.length;
        if (offset == 1) {
            b.write(0x9F);
        } else if (offset == 2) {
            b.write(0x1F);
            b.write(0x80);
        } else {
            b.write(0x1F);
            b.write(padByte(offset - 2), 0, offset - 2);
            b.write(0x80);
        }
        return b.toByteArray();
    }

    /**
     * pads msg to array of nr bytes with 0s
     *
     * @param msg initial message
     * @param nr  pads to the nr of bytes
     * @return zero-padded message
     */
    public static byte[] zeroPad(int nr, byte[] msg) {
        if (msg.length == nr) return msg;
        byte[] ret = new byte[nr];
        System.arraycopy(msg, 0, ret, 0, msg.length);
        return ret;
    }

    /**
     * pads msg to array of nr bytes with 0s from front
     *
     * @param msg initial message
     * @param nr  pads to the nr of bytes
     * @return zero-padded message
     */
    private static byte[] zeroLead(int nr, byte[] msg) {
        if (msg.length == nr) return msg;
        byte[] ret = new byte[nr];
        int offset = nr - msg.length;
        System.arraycopy(msg, 0, ret, offset, msg.length);
        return ret;
    }

    /**
     * pads msg to array of nr bytes with 0s from front
     *
     * @param msg initial message
     * @param nr  pads to the nr of ints
     * @return zero-padded message
     */
    public static int[] zeroLead(int nr, int[] msg) {
        if (msg.length == nr) return msg;
        int[] ret = new int[nr];
        int offset = nr - msg.length;
        System.arraycopy(msg, 0, ret, offset, msg.length);
        return ret;
    }

    /**
     * encode byte array to hex string
     * used for unit tests
     *
     * @param bytes byte string
     * @return hexstring
     */
    public static String bytesToHex(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * returns the length LSB of the integer array
     * since it is only needed for 32 bits, no array support
     *
     * @param in  integer array
     * @param len number of required bits
     * @return integer containing up to 32 LSB
     */
    public static int getLSBits(int[] in, int len) {
        if (len == 0) return 0;
        return in[in.length - 1] & ((1 << len) - 1);
    }

    /**
     * convert a byte array to a long
     *
     * @param in byte array
     * @return long with the value of the byte array
     */
    public static long toLong(byte[] in) {
        long val = 0;
        int len = in.length;
        if (len > 8)
            len = 8;
        for (int i = 0; i < len; i++) {
            val = (val << 8) + (in[i] & 0xff);
            //val += ((long) in[i] & 0xffL) << (8 * i);
        }
        return val;
    }

    /**
     * convert a byte array to a long
     *
     * @param in byte array
     * @return long with the value of the byte array
     */
    public static long toLong(int[] in) {
        return (long) in[0] << 32 | in[1] & 0xFFFFFFFFL;
    }

    /**
     * returns then len most significant bits of an integer array
     *
     * @param in  input
     * @param len keep len bits
     * @return len MSBits of in
     */
    public static int[] getMSBits(int[] in, int len) {
        BigInteger b = new BigInteger(convertToByte(in));
        BigInteger shifted = b.shiftRight(b.bitLength() - len);
        return convertToInt(shifted.toByteArray());
    }

    /**
     * returns then len most significant bits of a byte array
     *
     * @param in  input
     * @param len keep len bits
     * @return len MSBits of in
     */
    public static int[] getMSBits(byte[] in, int len) {
        BigInteger b = new BigInteger(in);
        int shiftby = b.bitLength() + 1 - len;
        if (shiftby < 0)
            return convertToInt(zeroLead(len / 8, in));
        BigInteger shifted = b.shiftRight(shiftby);
        return convertToInt(shifted.toByteArray());
    }

    /**
     * scale down the message to indices by interpreting m as Treeheight-bit unsigned integers
     * we assume that the message has at least height*trees bits
     * lazily taken out of the sphincs+ reference
     *
     * @param msg message to be broken down
     * @param k   number of FORS trees in sphincs+ paramsvery
     * @param a   treeheight, a parameter in sphincs+ params
     * @return message broken down in indices as an int array
     */
    public static int[] messageToIndices(byte[] msg, int k, int a) {
        int offset = 0;
        int[] indices = new int[k];
        for (int i = 0; i < k; i++) {
            indices[i] = 0; //possible omission
            for (int j = 0; j < a; j++) {
                indices[i] ^= ((msg[offset >> 3] >> (offset & 0x7)) & 0x1) << j;
                offset++;
            }
        }
        return indices;
    }
}
