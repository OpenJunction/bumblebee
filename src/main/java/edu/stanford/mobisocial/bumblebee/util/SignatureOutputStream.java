package edu.stanford.mobisocial.bumblebee.util;

import java.io.*;
import java.security.*;

/**
 * This class provides an outputstream which writes everything
 * to a Signature as well as to an underlying stream.
 */
public class SignatureOutputStream extends OutputStream
{

    private OutputStream target;
    private Signature sig;

    /**
     * creates a new SignatureOutputStream which writes to
     * a target OutputStream and updates the Signature object.
     */
    public SignatureOutputStream(OutputStream target, Signature sig) {
        this.target = target;
        this.sig = sig;
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

    public void write(byte[] b, int offset, int len)
        throws IOException
    {
        target.write(b, offset, len);
        try {
            sig.update(b, offset, len);
        }
        catch(SignatureException ex) {
            throw new IOException(ex);
        }
    }

    public void flush() 
        throws IOException
    {
        target.flush();
    }

    public void close() 
        throws IOException
    {
        target.close();
    }
}