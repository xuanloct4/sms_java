/*****************************************************************
 * Copyright (c) 1999-2001 Simplewire, Inc. All Rights Reserved.
 *
 * Simplewire grants you ("Licensee") a non-exclusive, royalty
 * free, license to use, modify and redistribute this software
 * in source and binary code form, provided that i) Licensee
 * does not utilize the software in a manner which is
 * disparaging to Simplewire.
 *
 * This software is provided "AS IS," without a warranty of any
 * kind. ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND
 * WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT, ARE
 * HEREBY EXCLUDED. SIMPLEWIRE AND ITS LICENSORS SHALL NOT BE
 * LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF
 * USING, MODIFYING OR DISTRIBUTING THE SOFTWARE OR ITS
 * DERIVATIVES. IN NO EVENT WILL SIMPLEWIRE OR ITS LICENSORS BE
 * LIABLE FOR ANY LOST REVENUE, PROFIT OR DATA, OR FOR DIRECT,
 * INDIRECT, SPECIAL, CONSEQUENTIAL, INCIDENTAL OR PUNITIVE
 * DAMAGES, HOWEVER CAUSED AND REGARDLESS OF THE THEORY OF
 * LIABILITY, ARISING OUT OF THE USE OF OR INABILITY TO USE
 * SOFTWARE, EVEN IF SIMPLEWIRE HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 *****************************************************************/

/*****************************************************************
 * Shows how to send a wireless message containing a profile
 * in Java.
 *
 * Please visit www.simplewire.com for sales and support.
 *
 * @author Simplewire, Inc.
 * @version 2.6.1
 * @since  jdk1.2
 *****************************************************************/

import com.simplewire.sms.*;

public class send_profile
{
	public static void main(String[] args) throws Exception
	{
		SMS sms = new SMS();

		// Subscriber Settings
		sms.setSubscriberID("123-456-789-12345");
		sms.setSubscriberPassword("Password Goes Here");

		// Message Settings
		sms.setMsgPin("+1 100 510 1234");
		sms.setMsgFrom("Demo");
		sms.setMsgCallback("+1 100 555 1212");

		// Smart Message Settings - View the manual for
		// more smart messaging options and acceptance of
		// raw hex data.
		sms.setOptPhone("nokia");
		sms.setMsgProfileName("myProfileName");
		sms.setMsgProfileRingtone("Simplewire:d=4,o=5,b=63:8a,8e,32a,32e,16a,8c6,8a,32c6,32a,16c6,8e6,8c6,32e6,32c6,16e6,8g6,32g,32p,16g,32c6,32g,16c6,8e6,32p");
		sms.setMsgProfileScreenSaverFilename("example.gif");

		System.out.println("Sending message to Simplewire...");

		// Send Message
		sms.msgSend();

		// Check For Errors
		if(sms.isSuccess())
		{
			System.out.println("Message was sent!");
		}
		else
		{
			System.out.println("Message was not sent!");
			System.out.println("Error Code: " + sms.getErrorCode());
			System.out.println("Error Description: " + sms.getErrorDesc());
			System.out.println("Error Resolution: " + sms.getErrorResolution() + "\n");
		}

	}
}
