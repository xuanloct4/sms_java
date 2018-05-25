/*
 * @(#)GssGetattrs.java	1.1 00/02/16
 *
 * Copyright 2000 Sun Microsystems, Inc. All Rights
 * Reserved.
 *
 * Sun grants you ("Licensee") a non-exclusive, royalty free,
 * license to use, modify and redistribute this software in source and
 * binary code form, provided that i) this copyright notice and license
 * appear on all copies of the software; and ii) Licensee does not utilize
 * the software in a manner which is disparaging to Sun.
 *
 * This software is provided "AS IS," without a warranty of any
 * kind. ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND
 * WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT, ARE HEREBY EXCLUDED. SUN
 * AND ITS LICENSORS SHALL NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY
 * LICENSEE AS A RESULT OF USING, MODIFYING OR DISTRIBUTING THE SOFTWARE
 * OR ITS DERIVATIVES. IN NO EVENT WILL SUN OR ITS LICENSORS BE LIABLE FOR
 * ANY LOST REVENUE, PROFIT OR DATA, OR FOR DIRECT, INDIRECT, SPECIAL,
 * CONSEQUENTIAL, INCIDENTAL OR PUNITIVE DAMAGES, HOWEVER CAUSED AND
 * REGARDLESS OF THE THEORY OF LIABILITY, ARISING OUT OF THE USE OF
 * OR INABILITY TO USE SOFTWARE, EVEN IF SUN HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 *
 * This software is not designed or intended for use in on-line
 * control of aircraft, air traffic, aircraft navigation or aircraft
 * communications; or in the design, construction, operation or
 * maintenance of any nuclear facility. Licensee represents and warrants
 * that it will not use or redistribute the Software for such purposes.
 */


import java.util.Hashtable;
import java.util.Enumeration;
 
import javax.naming.*;
import javax.naming.directory.*;

/*
 * Authenticate using SASL/GSSAPI/KerberosV5.
 * Retrieve attributes of a particular entry.
 * Requires ldapbp.jar, jaas.jar, and a SASL GSSAPI/KerberosV5 mechanism.
 */
class GssGetattrs {

public static void main(String[] args) {

    Hashtable env = new Hashtable(5, 0.75f);
    /*
     * Specify the initial context implementation to use.
     * This could also be set by using the -D option to the java program.
     * For example,
     *   java -Djava.naming.factory.initial=com.sun.jndi.ldap.LdapCtxFactory \
     *     Search
     */
    env.put(Context.INITIAL_CONTEXT_FACTORY, Env.INITCTX);

    /* Specify host and port to use for directory service */
    env.put(Context.PROVIDER_URL, Env.MY_SERVICE);

    // authentication information
    env.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");

    // Uncomment this to get no protection
    // env.put("javax.security.sasl.encryption.maximum", "0");

    try {
	/* get a handle to an Initial DirContext */
	DirContext ctx = new InitialDirContext(env);

	Attributes result = ctx.getAttributes(Env.ENTRYDN);

	if (result == null) {
	    System.out.println(Env.ENTRYDN + 
		"has none of the specified attributes.");
	} else {
	    /* print it out */
	    System.out.println(result);
	}
	ctx.close();
    } catch (NamingException e) {
	System.err.println("Getattrs example failed.");
	e.printStackTrace();
    }
}
}
