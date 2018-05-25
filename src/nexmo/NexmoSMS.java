package nexmo;

/* For more information
/https://github.com/Nexmo/nexmo-java
 */

import com.nexmo.client.NexmoClient;
import com.nexmo.client.auth.AuthMethod;
import com.nexmo.client.auth.TokenAuthMethod;
import com.nexmo.client.sms.SmsSubmissionResult;
import com.nexmo.client.sms.messages.TextMessage;

public class NexmoSMS {
    /* Commanline
    / curl -X POST  https://rest.nexmo.com/sms/json \
-d api_key=c08a6d3f \
-d api_secret=48MwjvZu4G4yfExN \
-d to=841675287976 \
-d from="NEXMO" \
-d text="Hello from Nexmo"
     */

    public static final String API_KEY = "c08a6d3f";
    public static final String API_SECRET = "48MwjvZu4G4yfExN";
    public static final String FROM_NUMBER = "NEXMO";
    public static final String TO_NUMBER = "841675287976";

    public static void main(String[] args) {
        AuthMethod auth = new TokenAuthMethod(API_KEY, API_SECRET);
        NexmoClient client = new NexmoClient(auth);
        System.out.println("From: " + FROM_NUMBER);
        System.out.println("To: " + TO_NUMBER);

        try {
            SmsSubmissionResult[] responses = client.getSmsClient().submitMessage(new TextMessage(
                    FROM_NUMBER,
                    TO_NUMBER,
                    "Hello from Nexmo!"));
            for (SmsSubmissionResult response : responses) {
                System.out.println(response);
            }
        }catch (Exception e) {
            System.out.println(e);
        }

    }
}
