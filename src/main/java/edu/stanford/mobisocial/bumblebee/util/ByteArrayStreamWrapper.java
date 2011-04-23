package edu.stanford.mobisocial.bumblebee.util;
import java.io.*;

/**
 * This class provides an outputstream which writes everything
 * to the provided byte array. An IOException will be thrown 
 * if the capacity of the byte array is exceeded.
 */
public class ByteArrayStreamWrapper extends OutputStream
{

    private final byte[] target;
    private int offset = 0;

    public ByteArrayStreamWrapper(byte[] b) {
        this.target = b;
    }

    public void write(int b)
        throws IOException
    {
        write(new byte[]{(byte)b});
    }

    public void write(byte[] b)
        throws IOException
    {
        write(b, 0, b.length);
    }

    public void write(byte[] b, int i, int len)
        throws IOException
    {
        if(len > (target.length - offset)) throw new IOException("Capacity of byte array exceeded!");
        System.arraycopy(b, i, target, offset, len);
        offset += len;
    }

    public void flush() 
        throws IOException
    {}

    public void close() 
        throws IOException
    {}
}