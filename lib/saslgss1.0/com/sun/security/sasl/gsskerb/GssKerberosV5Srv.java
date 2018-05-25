/*
 * @(#)GssKerberosV5Srv.java	1.2 00/02/16
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
public class GssKerberosV5Srv extends GssKerberosUtil implements SaslServer {
    private int handshakeStage = 0; 
    private GSSCredential cred;
    private String peer;
    
    /**
     * Creates a SASL mechanism with server credentials that it needs 
     * to participate in GSS-API/Kerberos v5 authentication exchange 
     * with the client.
     */
    public GssKerberosV5Srv(String protocol, String serverName,
	java.util.Hashtable props, CallbackHandler cbh) throws SaslException {
	    super(props);

	String service = protocol + "@" + serverName;

	try {
	    // Create the name for the requested service entity for Krb5 mech
	    GSSName serviceName = new GSSName(service,
		GSSName.NT_HOSTBASED_SERVICE, KRB5_OID);

	    cred = new GSSCredential(serviceName, GSSCredential.INDEFINITE,
		KRB5_OID, GSSCredential.ACCEPT_ONLY);

	    // %%% The steps for creating credentials are expensive.
	    // %%% Perhaps the credentials should be passed to the constructor
	    
	    // Create a context using the server's credentials
	    secCtx = new GSSContext(cred);

	    if ((protections&INTEGRITY_ONLY_PROTECTION) != 0) {
		// Might need integrity
		secCtx.requestInteg(true);
	    }
	    
	    if ((protections&PRIVACY_PROTECTION) != 0) {
		// Might need privacy
		secCtx.requestConf(true);
	    }
	} catch (GSSException e) {
	    throw new SaslException("Failure to initialize security context", e);
	}
    }


    /**
     * Processes the response data.
     * 
     * The client sends response data to which the server must
     * process using GSS_accept_sec_context.
     * As per RFC 2222, the GSS authenication completes (GSS_S_COMPLETE)
     * we do an extra hand shake to determine the negotiated security protection
     * and buffer sizes.
     *
     * @param responseData A non-null but possible empty byte array containing the
     * response data from the client.
     * @return A non-null byte array containing the challenge to be
     * sent to the client.
     */
    public byte[] evaluateResponse(byte[] responseData) throws SaslException {
	if (completed) {
	    throw new SaslException(
		"SASL authentication already complete");
	}

	switch (handshakeStage) {
	case 1:
	    return doFinalHandshake1(responseData);

	case 2:
	    return doFinalHandshake2(responseData);
	    
	default:
	    // Security context not established yet; continue with accept

	    try {
		byte[] gssOutToken = secCtx.accept(responseData,
		    0, responseData.length);

		if (secCtx.isEstablished()) {
		    handshakeStage = 1;

		    peer = secCtx.getSrcName().toString();
		    
		    if (gssOutToken == null) {
			return doFinalHandshake1(new byte[0]);
		    }
		}

		return gssOutToken;
	    } catch (GSSException e) {
		throw new SaslException("GSS initiate failed", e);
	    }
	}
    }

    private byte[] doFinalHandshake1(byte[] responseData) throws SaslException {
	try {
	    // Security context already established. responseData
	    // should contain no data
	    if (responseData != null && responseData.length > 0) {
		throw new SaslException(
		    "Final handshake expecting no response data from server");
	    }

	    // Construct 4 octets of data:
	    // First octet contains bitmask specifying protections supported
	    // 2nd-4th octets contains max receive buffer of server

	    byte[] gssInToken = new byte[4];
	    gssInToken[0] = protections;
	    intToNetworkByteOrder(recvMaxBufSize, gssInToken, 1, 3);

	    handshakeStage = 2;  // progress to next stage

	    return secCtx.wrap(gssInToken, 0, gssInToken.length,
		new MessageProp(0 /* gop */, false /* privacy */));
	} catch (GSSException e) {
	    throw new SaslException("Problem wrapping final handshake", e);
	}
    }

    private byte[] doFinalHandshake2(byte[] responseData) throws SaslException {
	try {
	    // Expecting 4 octets from client selected protection
	    // and client's receive buffer size
	    byte[] gssOutToken = secCtx.unwrap(responseData, 0,
		responseData.length, new MessageProp(0, false));

	    // First octet is a bit-mask specifying the selected protection
	    byte selectedProtection = gssOutToken[0];
	    if ((selectedProtection&protections) == 0) {
		throw new SaslException("Client selected unsupported protection: "
		    + selectedProtection);
	    }
	    if ((selectedProtection&PRIVACY_PROTECTION) != 0) {
		privacy = true;
		integrity = true;
	    } else if ((selectedProtection&INTEGRITY_ONLY_PROTECTION) != 0) {
		privacy = false;
		integrity = true;
	    } else if ((selectedProtection&NO_PROTECTION) != 0) {
		privacy = false;
		integrity = false;
	    } 

	    // 2nd-4th octets specifies maximum buffer size expected by
	    // client (in network byte order). This is the server's send
	    // buffer maximum.
	    int clntMaxBufSize = networkByteOrderToInt(gssOutToken, 1, 3);

	    // Determine the max send buffer size based on what the
	    // client is able to receive and our specified max
	    sendMaxBufSize = (sendMaxBufSize == 0) ? clntMaxBufSize :
		Math.min(sendMaxBufSize, clntMaxBufSize);

	    // Update context to limit size of returned buffer
	    rawSendSize = secCtx.getWrapSizeLimit(qop, privacy,
		sendMaxBufSize);

	    return null;
	} catch (GSSException e) {
	    throw new SaslException("Final handshake failed", e);
	}
    }

    public String getAuthorizationID() throws SaslException {
	if (completed) {
	    return peer;
	} else {
	    throw new SaslException("Not completed");
	}
    }
}
