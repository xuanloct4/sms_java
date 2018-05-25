/*
 * @(#)GssKerberosUtil.java	1.2 00/02/16
 *
 * Copyright 2000 Sun Microsystems, Inc. All Rights Reserved.
 *
 * Sun grants you ("Licensee") a non-exclusive, royalty free,
 * license to use, modify and redistribute this software in source and
 * binary code form, provided that i) this copyright notice and license
 * appear on all copies of the software; and ii) Licensee does not 
 * utilize the software in a manner which is disparaging to Sun.
 *
 * This software is provided "AS IS," without a warranty of any
 * kind. ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND
 * WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT, ARE 
 * HEREBY EXCLUDED.  SUN AND ITS LICENSORS SHALL NOT BE LIABLE 
 * FOR ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, 
 * MODIFYING OR DISTRIBUTING THE SOFTWARE OR ITS DERIVATIVES. IN 
 * NO EVENT WILL SUN OR ITS LICENSORS BE LIABLE FOR ANY LOST 
 * REVENUE, PROFIT OR DATA, OR FOR DIRECT, INDIRECT, SPECIAL,
 * CONSEQUENTIAL, INCIDENTAL OR PUNITIVE DAMAGES, HOWEVER 
 * CAUSED AND REGARDLESS OF THE THEORY OF LIABILITY, ARISING OUT 
 * OF THE USE OF OR INABILITY TO USE SOFTWARE, EVEN IF SUN HAS 
 * BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * 
 * This software is not designed or intended for use in on-line
 * control of aircraft, air traffic, aircraft navigation or aircraft
 * communications; or in the design, construction, operation or
 * maintenance of any nuclear facility. Licensee represents and warrants
 * that it will not use or redistribute the Software for such purposes.  
 */

package com.sun.security.sasl.gsskerb; 

import com.sun.security.sasl.preview.*;
import java.io.*;

// JGSS from DSTC; implements draft -00 of JGSS API
import com.dstc.security.kerberos.gssapi.*;

/**
 * The base class used by client and server implementations of GSSAPI/Kerberos.
 *
 * @author Rosanna Lee
 */
abstract class GssKerberosUtil {
    protected static final boolean debug = false;

    protected boolean completed = false;
    protected GSSContext secCtx = null;
    protected boolean privacy = false;
    protected boolean integrity = false;
    protected int qop = 0;	  // 0 means default quality of protection
    protected int minKeyLen = 0;  // 0=none; 1=integrity only; >1=integ + priv
    protected int maxKeyLen = 256;
    protected int sendMaxBufSize = 0;    // specified by peer but can override
    protected int recvMaxBufSize = 4096;
    protected int rawSendSize;
    protected byte protections;   // security layers we support

    protected GssKerberosUtil(java.util.Hashtable props) throws SaslException {
	// Parse properties  to set desired context options
	if (props != null) {
	    // Minimum key length
	    String prop = (String)props.get(MIN_KEY);
	    if (prop != null) {
		try {
		    minKeyLen = Integer.parseInt(prop);
		} catch (NumberFormatException e) {
		    throw new SaslException(
			"Property must be string representation of integer: " + 
			MIN_KEY);
		}
	    }
		
	    // Maximum key length
	    prop = (String)props.get(MAX_KEY);
	    if (prop != null) {
		try {
		    maxKeyLen = Integer.parseInt(prop);
		} catch (NumberFormatException e) {
		    throw new SaslException(
			"Property must be string representation of integer: " + 
			MAX_KEY);
		}
		// set quality of protection if user specifies max key length
		// otherwise, defaults to mechanism default
		qop = maxKeyLen;
	    }

	    if (maxKeyLen == 0) {
		protections = NO_PROTECTION;
	    } else if (maxKeyLen == 1) {
		protections = INTEGRITY_ONLY_PROTECTION;
		if (minKeyLen == 0) {
		    // no protection also acceptable
		    protections |= NO_PROTECTION;
		}
	    } else {
		protections = PRIVACY_PROTECTION;
		if (minKeyLen == 0) {
		    protections |= NO_PROTECTION|INTEGRITY_ONLY_PROTECTION;
		} else if (minKeyLen == 1) {
		    protections |= INTEGRITY_ONLY_PROTECTION;
		}
	    }

	    if (debug) {
		System.err.println("client protections: " + protections);
	    }

	    // max buf size
	    prop = (String)props.get(MAX_SEND_BUF);
	    if (prop != null) {
		try {
		    sendMaxBufSize = Integer.parseInt(prop);
		} catch (NumberFormatException e) {
		    throw new SaslException(
			"Property must be string representation of integer: " + 
			MAX_SEND_BUF);
		}
	    }
		
	    prop = (String)props.get(MAX_RECV_BUF);
	    if (prop != null) {
		try {
		    recvMaxBufSize = Integer.parseInt(prop);
		} catch (NumberFormatException e) {
		    throw new SaslException(
			"Property must be string representation of integer: " + 
			MAX_RECV_BUF);
		}
	    }
	}
    }

    /**
     * Retrieves this mechanism's name.
     *
     * @return  The string "GSSAPI".
     */
    public String getMechanismName() {
	return "GSSAPI";
    }

    /**
     * Determines whether this mechanism has completed.
     * GSSAPI completes when server returns GSS_S_COMPLETE.
     *
     * @return true if has completed; false otherwise;
     */
    public boolean isComplete() {
	return completed;
    }


    /**
      * Returns the input stream from which to read SASL buffers.
      * If neither privacy nor integrity is needed, this is the identity function.
      * Otherwise, return a stream that does GSSContext.wrap().
      *
      * @return <tt>src</tt>
      * @throws IOException If this method is called before the client has
      *   has completed.
      */
    public InputStream getInputStream(InputStream src) throws IOException {
	if (completed) {
	    if (!privacy && !integrity) {
		return src;    // Don't need a different stream
	    } else {
		// Create stream that does secCtx.unwrap()
		return new GssInputStream(src);
	    }
	} else {
	    throw new SaslException("Not completed");
	}
    }

    /**
      * Returns the output stream to which to write data to be encapsulated
      * inside a SASL buffer for transmission to the server.
      * If neither privacy nor integrity is needed, this is the identity function.
      * Otherwise, return a stream that does GSSContext.unwrap().
      *
      * @return <tt>dest</tt>
      * @throws IOException If this method is called before the client has
      *   has completed.
      */
    public OutputStream getOutputStream(OutputStream dest) throws IOException {
	if (completed) {
	    if (!privacy && !integrity) {
		return dest;   // Don't need a different stream
	    } else {
		// Create stream that does secCtx.wrap()
		return new GssOutputStream(dest);
	    }
	} else {
	    throw new SaslException("Not completed");
	}
    }

    protected static void intToNetworkByteOrder(int num, byte[] buf, int start, 
	int count) {
	if (count > 4) {
	    throw new IllegalArgumentException("Cannot handle more than 4 bytes");
	}

	for (int i = count-1; i >= 0; i--) {
	    buf[start+i] = (byte)(num & 0xff);
	    num >>>= 8;
	}
    }

    protected static int networkByteOrderToInt(byte[] buf, int start, int count) {
	if (count > 4) {
	    throw new IllegalArgumentException("Cannot handle more than 4 bytes");
	}

	int answer = 0;

        for (int i = 0; i < count; i++) {
	    answer <<= 8;
	    answer |= ((int)buf[start+i] & 0xff);
	}
	return answer;
    }

    // ---------------- property names -----------------
    // default 0 (no protection); 1 (integrity only)
    static final protected String MIN_KEY = "javax.security.sasl.encryption.minimum";

    // default 256
    static final protected String MAX_KEY = "javax.security.sasl.encryption.maximum";

    // 
    static final protected String MAX_SEND_BUF = "javax.security.sasl.buffer.send";
    static final protected String MAX_RECV_BUF = "javax.security.sasl.maxbuffer";

    static final protected String KRB5_OID_STR = "1.2.840.113554.1.2.2";
    static final protected Oid KRB5_OID = new Oid(KRB5_OID_STR);

    static final protected byte NO_PROTECTION = (byte)1;
    static final protected byte INTEGRITY_ONLY_PROTECTION = (byte)2;
    static final protected byte PRIVACY_PROTECTION = (byte)4;

    // --------------- utility classes ---------------

    class GssInputStream extends InputStream {
	private MessageProp msgProp;    // QOP and privacy for unwrap
	private byte[] buf;	        // buffer for storing processed bytes
	private int bufPos;		// read position in buf
	private byte[] lenBuf = new byte[4];  // buffer for storing length
	private InputStream in;		// underlying input stream

	GssInputStream(InputStream in) {
	    super();
	    this.in = in;
	    msgProp = new MessageProp(qop, privacy);
	    buf = new byte[recvMaxBufSize];
	}

	public int read() throws IOException {
	    byte[] inBuf = new byte[1];
	    int count = read(inBuf, 0, 1);
	    if (count > 0) {
		return inBuf[0];
	    } else {
		throw new EOFException();
	    }
	}

	public int read(byte[] inBuf, int start, int count) throws IOException {
	    if (bufPos >= buf.length) {
		fill();   // read next SASL buffer
	    }

	    int avail = buf.length - bufPos;
	    if (count > avail) {
		// Requesting more that we have stored
		// Return all that we have; next invocation of read() will
		// trigger fill()
		System.arraycopy(buf, bufPos, inBuf, start, avail);
		bufPos = buf.length;
		return avail;
	    } else {
		// Requesting less than we have stored
		// Return all that was requested
		System.arraycopy(buf, bufPos, inBuf, start, count);
		bufPos += count;
		return count;
	    }
	}

	/**
	 * Fills the buf with more data by reading a SASL buffer, unwrapping it,
 	 * and leaving the bytes in buf for read() to return.
	 */
	private void fill() throws IOException {
	    // Read in length of buffer
	    readFully(lenBuf, 4);
	    int len = networkByteOrderToInt(lenBuf, 0, 4);

	    if (debug) {
		System.err.println("reading " + len + " bytes from network");
	    }

	    // Read SASL buffer
	    byte[] saslBuffer = new byte[len];
	    readFully(saslBuffer, len);

	    // Unwrap
	    try {
		buf = secCtx.unwrap(saslBuffer, 0, len, msgProp);
	    } catch (GSSException e) {
		throw new SaslException("Problems unwrapping SASL buffer", e);
	    }

	    if (buf.length > recvMaxBufSize) {
		throw new SaslException(
		    "GSS unwrap returned a buffer size (" + buf.length +
		    ") that exceeds the negotiated limit:" + recvMaxBufSize);
	    }
	    bufPos = 0;
	}

	/**
  	 * Read requested number of bytes before returning.
	 */
	private void readFully(byte[] inBuf, int total) throws IOException {
	    int count, pos = 0;

	    if (debug) {
		System.err.println("readFully " + total + " from " + in);
	    }

	    while (total > 0) {
		count = in.read(inBuf, pos, total);

		if (debug) {
		    System.err.println("readFully read" + count);
		}

		if (count == -1 ) {
		    throw new EOFException();
		}
		pos += count;
		total -= count;
	    }
	}

	public int available() throws IOException {
	    return buf.length - bufPos;
	}

	public void close() throws IOException {
	    in.close();
	}
    }

    class GssOutputStream extends FilterOutputStream {
	private MessageProp msgProp;    // QOP and privacy for wrap
	private byte[] lenBuf = new byte[4];  // buffer for storing length

	GssOutputStream(OutputStream out) {
	    super(out);

	    if (debug) {
		System.err.println("GssOutputStream: " + out);
	    }
	    msgProp = new MessageProp(qop, privacy);
	}

	public void write(int b) throws IOException {
	    byte[] buffer = new byte[1];
	    buffer[0] = (byte)b;
	    write(buffer, 0, 1);
	}

	public void write(byte[] buffer, int offset, int total)
	    throws IOException {

	    int count;
	    byte[] gssOutToken, saslBuffer;
	    
	    // "Packetize" buffer to be within rawSendSize
	    if (debug) {
		System.err.println("Total size: " + total);
	    }

	    for (int i = 0; i < total; i += rawSendSize) {

		// Calculate length of current "packet"
		count = (total - i) < rawSendSize ? (total - i) : rawSendSize;

		// Generate GSS token 
		try {
		    gssOutToken = secCtx.wrap(buffer, offset+i, count, msgProp);

		} catch (GSSException e) {
		    throw new SaslException("Problem performing GSS wrap", e);
		}

		// Write out length
		intToNetworkByteOrder(gssOutToken.length, lenBuf, 0, 4);

		if (debug) {
		    System.err.println("sending size: " + gssOutToken.length);
		}
		out.write(lenBuf, 0, 4);

		// Write out GSS token
		out.write(gssOutToken, 0, gssOutToken.length);
	    }
	}
    }
}
