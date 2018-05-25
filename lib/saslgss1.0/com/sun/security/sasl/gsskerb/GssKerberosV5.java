/*
 * @(#)GssKerberosV5.java	1.2 00/02/16
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

// JAAS
import javax.security.auth.callback.CallbackHandler;

// JGSS from DSTC; implements draft -00 of JGSS API
import com.dstc.security.kerberos.gssapi.*;

/**
  * Implements the GSSAPI SASL mechanism for Kerberos V5. 
  * (<A HREF="ftp://ftp.isi.edu/in-notes/rfc2222.txt">RFC 2222</A>,
  * <a HREF="http://www.ietf.org/internet-drafts/draft-ietf-cat-sasl-gssapi-00.txt">draft-ietf-cat-sasl-gssapi-00.txt</a>).
  *
  * @author Rosanna Lee
  */
public class GssKerberosV5 extends GssKerberosUtil implements SaslClient {
    private boolean finalHandshake = false; 
    private boolean mutual = false;       // default false
    static final private String MUTUAL_AUTH =
    	"javax.security.sasl.server.authentication";

    /**
     * Creates a SASL mechanism with client credentials that it needs 
     * to participate in GSS-API/Kerberos v5 authentication exchange 
     * with the server.
     */
    public GssKerberosV5(String authzID, String protocol, String serverName,
	java.util.Hashtable props, CallbackHandler cbh) throws SaslException {
	    super(props);

	String service = protocol + "@" + serverName;

	try {
	    // Create the name for the requested service entity for Krb5 mech
	    GSSName acceptorName = new GSSName(service,
		GSSName.NT_HOSTBASED_SERVICE, KRB5_OID);

	    // Create a context using default credentials for Krb5 mech
	    secCtx = new GSSContext(acceptorName,
		KRB5_OID, /* mechanism */
		null,       /* default credentials */
		GSSContext.INDEFINITE);

	    // Parse properties  to set desired context options
	    if (props != null) {
		// Mutual authentication
		String prop = (String)props.get(MUTUAL_AUTH);
		if (prop != null) {
		    mutual = "true".equalsIgnoreCase(prop);
		}
	    }
	    secCtx.requestMutualAuth(mutual);

	    if ((protections&INTEGRITY_ONLY_PROTECTION) != 0) {
		// Might need integrity
		secCtx.requestInteg(true);
	    }
	    
	    if ((protections&PRIVACY_PROTECTION) != 0) {
		// Might need privacy
		secCtx.requestConf(true);
	    }

	    // %%% The final handshake breaks in Active Directory 
	    // if we don't set confidentiality and integrity here
	    secCtx.requestConf(true);
	    secCtx.requestInteg(true);
		
	} catch (GSSException e) {
	    throw new SaslException("Failure to initialize security context", e);
	}
    }

    public boolean hasInitialResponse() {
	return true;
    }

    /**
     * Processes the challenge data.
     * 
     * The server sends a challenge data using which the client must
     * process using GSS_Init_sec_context.
     * As per RFC 2222, when GSS_S_COMPLETE is returned, we do
     * an extra handshake to determine the negotiated security protection
     * and buffer sizes.
     *
     * @param challengeData A non-null byte array containing the
     * challenge data from the server.
     * @return A non-null byte array containing the response to be
     * sent to the server.
     */
    public byte[] evaluateChallenge(byte[] challengeData) throws SaslException {
	if (completed) {
	    throw new SaslException(
		"SASL authentication already complete");
	}

	if (finalHandshake) {
	    return doFinalHandshake(challengeData);
	} else {

	    // Security context not established yet; continue with init

	    try {
		byte[] gssOutToken = secCtx.init(challengeData,
		    0, challengeData.length);

		if (secCtx.isEstablished()) {
		    finalHandshake = true;
		    if (gssOutToken == null) {
			// RFC 2222 7.2.1:  Client responds with no data
			return new byte[0];
		    }
		}

		return gssOutToken;
	    } catch (GSSException e) {
		throw new SaslException("GSS initiate failed", e);
	    }
	}
    }

    public byte[] doFinalHandshake(byte[] challengeData) throws SaslException {
	try {
	    // Security context already established. challengeData
	    // should contain security layers and server's maximum buffer size

	    if (debug) {
		System.err.println("size: " + challengeData.length);
		for (int i = 0; i < challengeData.length; i++) {
		    System.err.println(Integer.toHexString(challengeData[i]));
		}
	    }

	    // %%% Active Directory expects an extra empty exchange
	    if (challengeData.length == 0) {
		return new byte[0];
	    }

	    byte[] gssOutToken = secCtx.unwrap(challengeData, 0,
		challengeData.length, new MessageProp(0, false));

	    // First octet is a bit-mask specifying the protections
	    // supported by the server
	    // Client selects highest available protection requested
	    byte commonProtections = (byte)(protections&gssOutToken[0]);
	    byte selectedProtection;

	    if (debug) {
		System.err.println("Server protections: " + gssOutToken[0]);
	    }

	    if ((commonProtections&PRIVACY_PROTECTION) != 0) {
		selectedProtection = PRIVACY_PROTECTION;
		privacy = true;
		integrity = true;
	    } else if ((commonProtections&INTEGRITY_ONLY_PROTECTION) != 0) {
		selectedProtection = INTEGRITY_ONLY_PROTECTION;
		privacy = false;
		integrity = true;
	    } else if ((commonProtections&NO_PROTECTION) != 0) {
		selectedProtection = NO_PROTECTION;
		privacy = false;
		integrity = false;
	    } else {
		throw new SaslException(
		    "No common protection layer between client and server");
	    }

	    // 2nd-4th octets specifies maximum buffer size expected by
	    // server (in network byte order)
	    int srvMaxBufSize = networkByteOrderToInt(gssOutToken, 1, 3);

	    // Determine the max send buffer size based on what the
	    // server is able to receive and our specified max
	    sendMaxBufSize = (sendMaxBufSize == 0) ? srvMaxBufSize :
		Math.min(sendMaxBufSize, srvMaxBufSize);

	    // Update context to limit size of returned buffer
	    rawSendSize = secCtx.getWrapSizeLimit(qop, privacy,
		sendMaxBufSize);

	    // %%% getWrapSizeLimit() always returns 0 in DSTC code
	    if (rawSendSize == 0) {
		rawSendSize = 4096;
	    }

	    if (debug) {
		System.err.println("server max recv size: " + srvMaxBufSize);
		System.err.println("rawSendSize: " + rawSendSize);
	    }

	    // Construct negotiated security layers and client's max
	    // receive buffer size
	    byte[] gssInToken = new byte[4];
	    gssInToken[0] = selectedProtection;

	    if (debug) {
		System.err.println("selected protection: " + selectedProtection);
		System.err.println("privacy: " + privacy);
		System.err.println("integrity: " + integrity);
	    }

	    intToNetworkByteOrder(recvMaxBufSize, gssInToken, 1, 3);

	    gssOutToken = secCtx.wrap(gssInToken,
		0, gssInToken.length,
		new MessageProp(0 /* gop */, false /* privacy */));

	    completed = true;  // server authenticated

	    return gssOutToken;
	} catch (GSSException e) {
	    throw new SaslException("Final handshake failed", e);
	}
    }
}
