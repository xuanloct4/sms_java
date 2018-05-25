/*
 * @(#)Env.java	1.1 00/02/16
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

public class Env {

/*
 * Initial context implementation to use.
 */
public static String INITCTX = "com.sun.jndi.ldap.LdapCtxFactory";

/*
 * Host name and port number of LDAP server
 */
public static String MY_SERVICE = "ldap://localhost:389";

/*
 * DN of directory manager entry.  This entry should have write access to
 * the entire directory.
 */
public static String MGR_DN = "cn=Directory Manager, o=Ace Industry, c=US";

/*
 * Password for manager DN.
 */
public static String MGR_PW = "secret99";

/*
 * Subtree to search
 */
public static String MY_SEARCHBASE = "o=Ace Industry, c=US";

/*
 * Subtree to modify
 */
public static String MY_MODBASE = "o=Ace Industry, c=US";

/* 
 * Filter to use when searching.  This one searches for all entries with the
 * surname (last name) of "Jensen".
 */
public static String MY_FILTER = "(sn=Jensen)";

/*
 * Entry to retrieve
 */
public static String ENTRYDN = "cn=Barbara Jensen, ou=Product Development, o=Ace Industry, c=US";
};

