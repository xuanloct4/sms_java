package twilio;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;


import java.util.ArrayList;
import java.util.List;

public class TwilioSMS {
    /* Commandline
    / curl 'https://api.twilio.com/2010-04-01/Accounts/ACfc02db9e3910297510a282b34302e876/Messages.json' -X POST \
--data-urlencode 'To=+841675287976' \
--data-urlencode 'From=+16029009491' \
--data-urlencode 'Body=Hello' \
-u ACfc02db9e3910297510a282b34302e876:3080b78ee79f65683026105bcfd381f5
     */

    // Find your Account Sid and Token at twilio.com/user/account
    public static final String ACCOUNT_SID = "ACfc02db9e3910297510a282b34302e876";
    public static final String AUTH_TOKEN = "3080b78ee79f65683026105bcfd381f5";

    public static void main(String[] args) {
        Twilio.init(ACCOUNT_SID, AUTH_TOKEN);

        Message message = Message.creator(new PhoneNumber("+841675287976"),
                new PhoneNumber("+16029009491"),
                "This is the ship that made the Kessel Run in fourteen parsecs?").create();

        System.out.println(message.getSid());
    }
}
