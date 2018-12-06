# Enable HTML Templates in EmailOTP

Use this configurations if you need to use HTML Templates in the Emails.
**This feature is supported from Identity Server v5.6 onwards**.

1. Configure Email settings in \<IS_HOME>/repository/conf/output-event-adapters.xml file. 
```
<adapterConfig type="email">
    <!-- Comment mail.smtp.user and mail.smtp.password properties to support connecting SMTP servers which use trust
        based authentication rather username/password authentication -->
    <property key="mail.smtp.from">abcd@gmail.com</property>
    <property key="mail.smtp.user">abcd</property>
    <property key="mail.smtp.password">xxxx</property>
    <property key="mail.smtp.host">smtp.gmail.com</property>
    <property key="mail.smtp.port">587</property>
    <property key="mail.smtp.starttls.enable">true</property>
    <property key="mail.smtp.auth">true</property>
    <!-- Thread Pool Related Properties -->
    <property key="minThread">8</property>
    <property key="maxThread">100</property>
    <property key="keepAliveTimeInMillis">20000</property>
    <property key="jobQueueSize">10000</property>
</adapterConfig>
```
2. Open \<IS_HOME>/repository/conf/identity/application-authentication.xml and add the following parameter into 
EmailOTP AuthenticationConfig element. 

```<Parameter name="useEventHandlerBasedEmailSender">true</Parameter>```

Example:

    <AuthenticatorConfig name="EmailOTP" enabled="true">
            <Parameter name="GmailClientId">gmailClientIdValue</Parameter>
            <Parameter name="GmailClientSecret">gmailClientSecretValue</Parameter>
            <Parameter name="SendgridAPIKey">sendgridAPIKeyValue</Parameter>
            <Parameter name="GmailRefreshToken">gmailRefreshTokenValue</Parameter>
            <Parameter name="GmailEmailEndpoint">https://www.googleapis.com/gmail/v1/users/[userId]/messages/send</Parameter>
            <Parameter name="SendgridEmailEndpoint">https://api.sendgrid.com/api/mail.send.json</Parameter>
            <Parameter name="accessTokenRequiredAPIs">Gmail</Parameter>
            <Parameter name="apiKeyHeaderRequiredAPIs">Sendgrid</Parameter>
            <Parameter name="SendgridFormData">sendgridFormDataValue</Parameter>
            <Parameter name="SendgridURLParams">sendgridURLParamsValue</Parameter>
            <Parameter name="GmailAuthTokenType">Bearer</Parameter>
            <Parameter name="GmailTokenEndpoint">https://www.googleapis.com/oauth2/v3/token</Parameter>
            <Parameter name="SendgridAuthTokenType">Bearer</Parameter>
            <Parameter name="redirectToMultiOptionPageOnFailure">false</Parameter>
            <Parameter name="useEventHandlerBasedEmailSender">true</Parameter>
    </AuthenticatorConfig>
        

3. Start the Identity Server.

### Configure the Email Templates
1. Login to the Carbon Console and Goto **Manage > Email Templates > Add** and click on **Add Email Template Type** to add a 
new Email Template type. 
2. Use **EmailOTP** as the **Template Display Name** and click **Add**.
3. Goto **Manage > Email Templates > Add** and click on **Add Email Template**. 
4. Select the **EmailOTP** template type from the **Email Template Type** dropdown list and complete the form with 
parameters as follows.

|Parameter Name| Value|
|:---|:---|
|**Template Name**|EmailOTP|
|**Select the Template Language**|English (United States)|
|**Email Content Type**|text/html|
|**Subject**|WSO2 IS Email OTP|
|**Email Body**|Refer [Email Template](#email-template)| 
|**Email Footer**|---|

5. Click **Add**.
 6. To test whether the email template is applied, follow the **Test the sample** section in [here](config.md).
### Email Template

    <table align="center" cellpadding="0" cellspacing="0" border="0" width="100%"bgcolor="#f0f0f0">
            <tr>
            <td style="padding: 30px 30px 20px 30px;">
                <table cellpadding="0" cellspacing="0" border="0" width="100%" bgcolor="#ffffff" style="max-width: 650px; margin: auto;">
                <tr>
                    <td colspan="2" align="center" style="background-color: #333; padding: 40px;">
                        <a href="http://wso2.com/" target="_blank"><img src="http://cdn.wso2.com/wso2/newsletter/images/nl-2017/wso2-logo-transparent.png" border="0" /></a>
                    </td>
                </tr>
                <tr>
                    <td colspan="2" align="center" style="padding: 50px 50px 0px 50px;">
                        <h1 style="padding-right: 0em; margin: 0; line-height: 40px; font-weight:300; font-family: 'Nunito Sans', Arial, Verdana, Helvetica, sans-serif; color: #666; text-align: left; padding-bottom: 1em;">
                            WSO2 IS Email OTP
                        </h1>
                    </td>
                </tr>
                <tr>
                    <td style="text-align: left; padding: 0px 50px;" valign="top">
                        <p style="font-size: 18px; margin: 0; line-height: 24px; font-family: 'Nunito Sans', Arial, Verdana, Helvetica, sans-serif; color: #666; text-align: left; padding-bottom: 3%;">
                            Hi {{user.claims.givenname}},
                        </p>
                        <p style="font-size: 18px; margin: 0; line-height: 24px; font-family: 'Nunito Sans', Arial, Verdana, Helvetica, sans-serif; color: #666; text-align: left; padding-bottom: 3%;">
                            Please use this one time password {{OTPCode}} to sign in to your application
                        </p>
                    </td>
                </tr>
                <tr>
                    <td style="text-align: left; padding: 30px 50px 50px 50px" valign="top">
                        <p style="font-size: 18px; margin: 0; line-height: 24px; font-family: 'Nunito Sans', Arial, Verdana, Helvetica, sans-serif; color: #505050; text-align: left;">
                            Thanks,<br/>WSO2 Identity Server Team
                        </p>
                    </td>
                </tr>
                <tr>
                    <td colspan="2" align="center" style="padding: 20px 40px 40px 40px;" bgcolor="#f0f0f0">
                        <p style="font-size: 12px; margin: 0; line-height: 24px; font-family: 'Nunito Sans', Arial, Verdana, Helvetica, sans-serif; color: #777;">
                            &copy; 2018
                            <a href="http://wso2.com/" target="_blank" style="color: #777; text-decoration: none">WSO2</a>
                            <br>
                            787 Castro Street, Mountain View, CA 94041.
                        </p>
                    </td>
                </tr>
                </table>
            </td>
        </tr>
    </table>

