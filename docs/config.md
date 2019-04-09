# Configuring Multi-factor Authentication using EmailOTP
This section provides the instructions to configure multi-factor authentication (MFA) using Email One Time Password (Email OTP) in WSO2 Identity Server (WSO2 IS). The Email OTP enables a one-time password (OTP) to be used at the second step of MFA. For more information on the WSO2 Identity Server Versions supported by the connector, see the IS Connector store.

Let's take a look at the tasks you need to follow to configure MFA using Email OTP:

- [Enabling email configuration on WSO2 IS](#enabling-email-configuration-on-wso2-is)
- [Configure the Email OTP provider](#configure-the-email-otp-provider)
- [Deploy the travelocity.com sample](#deploy-the-travelocity-sample)
- [Configure the Identity Provider](#configure-the-identity-provider)
- [Configure the Service Provider](#configure-the-service-provider)
- [Update the email address of the user](#update-the-email-address-of-the-user)
- [Configure the user claims](#configure-the-user-claims)
- [Test the sample](#test-the-sample)
- [Using HTML Templates in Emails](html-support.md)

**Before you begin!**

   To ensure you get the full understanding of configuring Email OTP with WSO2 IS, the sample travelocity application is used in this use case. The samples run on the Apache Tomcat server and are written based on Servlet 3.0. Therefore, download Tomcat 7.x from here.
   Install Apache Maven to build the samples. For more information, see Installation Prerequisites.

### Enabling email configuration on WSO2 IS

Follow the steps below to configure WSO2 IS to send emails once the Email OTP is enabled.

If you need to use HTML Templates in emails, skip this and check [Using HTML Templates in Emails](html-support.md).

   1. Shut down the server if it is running.

   2. Open the  <IS_HOME>/repository/conf/axis2/axis2.xml file, uncomment the transportSender name = "mailto" 
   configurations, and update the following properties:
   
   |||
   |---|---|
   |**mail.smtp.from**|Provide the email address of the SMTP account.|
   |**mail.smtp.user**|Provide the username of the SMTP account.|
   |**mail.smtp.password**|Provide the password of the SMTP account.|

    <transportSender  name="mailto"
    class="org.apache.axis2.transport.mail.MailTransportSender">
        <parameter  name="mail.smtp.from">{SENDER'S_EMAIL_ID}</parameter>
        <parameter  name="mail.smtp.user">{USERNAME}</parameter>
        <parameter  name="mail.smtp.password">{PASSWORD}</parameter>
        <parameter  name="mail.smtp.host">smtp.gmail.com</parameter>
        <parameter  name="mail.smtp.port">587</parameter>
        <parameter  name="mail.smtp.starttls.enable">true</parameter>
        <parameter  name="mail.smtp.auth">true</parameter>
    </transportSender>

   3. Comment out the \<module ref="addressing"/> property to avoid syntax errors.
   
     <!-- <module ref="addressing"/> -->

   4.  Add the following email template to the <IS_HOME>/repository/conf/email/email-admin-config.xml.
    
    <configuration type="EmailOTP" display="idleAccountReminder" locale="en_US" emailContentType="text/html">
       <targetEpr></targetEpr>
       <subject>WSO2 IS Email OTP</subject>
       <body>
          Hi,
          Please use this one time password {OTPCode} to sign in to your application.
       </body>
       <footer>
          Best Regards,
          WSO2 Identity Server Team
          http://www.wso2.com
       </footer>
       <redirectPath></redirectPath>
    </configuration>

   5. Configure the following properties in the <PRODUCT_HOME>/repository/conf/identity/identity-mgt.properties file to
    true.

    Authentication.Policy.Enable=true
    Authentication.Policy.Check.OneTime.Password=true

   6. Add the following configuration to the <IS_HOME>/repository/conf/identity/application-authentication.xml file 
   under the <AuthenticatorConfigs> section.

    <AuthenticatorConfig name="EmailOTP" enabled="true">     
          <Parameter name="EMAILOTPAuthenticationEndpointURL">https://localhost:9443/emailotpauthenticationendpoint/emailotp.jsp</Parameter>
          <Parameter name="EmailOTPAuthenticationEndpointErrorPage">https://localhost:9443/emailotpauthenticationendpoint/emailotpError.jsp</Parameter>
          <Parameter name="EmailAddressRequestPage">https://localhost:9443/emailotpauthenticationendpoint/emailAddress.jsp</Parameter>
          <Parameter name="usecase">association</Parameter>
          <Parameter name="secondaryUserstore">primary</Parameter>
          <Parameter name="EMAILOTPMandatory">false</Parameter>
          <Parameter name="sendOTPToFederatedEmailAttribute">false</Parameter>
          <Parameter name="federatedEmailAttributeKey">email</Parameter>
          <Parameter name="EmailOTPEnableByUserClaim">true</Parameter>
          <Parameter name="CaptureAndUpdateEmailAddress">true</Parameter>
          <Parameter name="showEmailAddressInUI">true</Parameter>
    </AuthenticatorConfig>
   
   **Parameter definitions.**
   
   |Parameter|Description|Sample Value|
   |:---------|:-----------|----|
   |usecase   |This parameter defines how the email ID will be retrieved. The default value is local.<br> (Check [Usecase definitions](#usecase-definitions) for more details.)| - local<br> - association<br> - userAttribute<br> - subjectUri|
   |secondaryUserstore|You can define multiple user stores per tenant as comma separated values. <br>Example: <br>\<Parameter name="secondaryUserstore">jdbc, abc, xyz\</Parameter><br> The user store configurations are maintained per tenant:<br> If you use a super tenant, set all the parameter values into the <IS_HOME>/repository/conf/identity/application-authentication.xml file under the AuthenticatorConfigs section.<br>If you use a tenant,<br> Upload the same XML file (application-authentication.xml) into a location (/_system/governance/EmailOTP).<br> Create the collection named EmailOTP, add the resource and upload the application-authentication. xml file into the registry.<br>While doing the authentication,thesysetmfirstcheckswhetherthereisanXML file uploaded to the registry. If that is so, it reads it from the registry but does not take the local file. If there is no file in the registry, then it only takes the property values from the local file.<br>You can use the registry or local file to get the property values.<br>|
   |EMAILOTPMandatory|This parmeter defines whther the EmailOTP is enforced as the second step of the 2FA/MFA or not.<br> If the user is not found in the active directory where the parameter is set to true, the OTP is directly sent to the email address defined in the claims set.<br> If the user is not found in the active directory where the parameter is set to false , the authentication flow terminates at the first step of the 2FA/MFA.|- true<br> - false
   |sendOTPToFederatedEmailAttribute|When the EMAILOTPMandatory and this parameter are set to true and the user is not found in the active directory, the OTPissetn to the mail defined in the federated authenticator claim.<br><br>When the EMAILOTPMandatory is set to false, an error page gets displayed.<br><br>When the EMAILOTPMandatory is set to false and the user is not found in the active directory, the authentication mechanism terminates at the first step of the 2FA/MFA. This parameter is not required in such a scenario.|- true <br> -false|
   |federatedEmailAttributeKey|This parameter identifies the email attribute of the federated authenticator, e.g. Foursquare. <br> Set this parameter if the sendOTPToFederatedEmailAttribute is set to true. Example:http://wso2.org/foursquare/claims/email||
   |EmailOTPEnableByUserClaim|This parameter enables the user to overidethefunctionalitydefinedattheEMAILOTPMandatory parameter.<br>* If this parameter and the EMAILOTPMandatory parameters are set to true, the user can either enable or disable the EmailOTP functionality.<br>* If this parameter is set to false where the EMAILOTPMandatory parameter is set to true, the user gets redirected to an error page.<br>If this parameter and the EMAILOTPMandatory parameters are set to false, the authentication flow terminates at the first step of the 2FA/MFA.<br>* If the user is not available in the active directory|- true <br> - false|
   |CaptureAndUpdateEmailAddress|This parameter enables the user to update the email address that is used to send the OTP, at the first login where the email address is not previously set.|- true <br>- false|
   |EmailAddressRequestPage|This parameter enables to display a page that requests for an email address where<br><br>The user has not registered an email address.<br>Sending OTP is defined as the second step of 2FA/MFA.<br>The CaptureAndUpdateEmailAddress parameter is set to true.<br><br>Example: https://localhost:9443/emailotpauthenticationendpoint/emailAddress.jsp ||
   |showEmailAddressInUI|This parameter enables to display the email address to which the OTP is sent to on the UI.|- true <br> - false|
   
   7. Start WSO2 IS.

### Configure the Email OTP provider
Note:

    If you have already enabled the SMTP transport sender to send the OTP, you would not have to configure Gmail APIs.So you can skip the following steps.
You can send the One Time Password (OTP) using Gmail APIs or using SendGrid. Follow the steps given below to configure Gmail APIs as the mechanisam to send the OTP.

   1. Create a Google account at [https://gmail.com](https://gmail.com).
    
   2. Got to [https://console.developers.google.com](https://console.developers.google.com) and click **ENABLE APIS AND SERVICES**.
    
   3. Search for Gmail API and click on it.

   4. Click **Enable** to enable the Gmail APIs.

   _**Why is this needed?**_

   _If you do not enable the Gmail APIs, you run in to a 401 error when trying out step13._


   5. Click **Credentials** and click **Create** to create a new project.

   6. Click **Credentials** and click the **Create credentials** drop-down.

   7. Select **OAuth client ID** option.
   
   ![](images/image2017-11-17_18-2-24.png)
   
   8. Click **Configure consent screen**.
   
   ![](images/Configure-Consent-Screen.png)
   
   9. Enter the Product name that needs to be shown to users, enter values to any other fields you prefer to update, 
   and click **Save**.

   10. Select the **Web application** option.
   
   Enter https://localhost:9443/commonauth as the **Authorize redirect URIs** text-box, and click **Create**.
    
   ![](images/Authorize-Redirect-URIs.png)

   The client ID and the client secret are displayed.
    Copy the client ID and secret and keep it in a safe place as you require it for the next step.

   ![](images/image2017-11-17_18-18-47.png)

   11. Copy the URL below and replace the <ENTER_CLIENT_ID> tag with the generated Client ID. This is required to 
   generate the authorization code.
   Format
   
    https://accounts.google.com/o/oauth2/auth?redirect_uri=https%3A%2F%2Flocalhost%3A9443%2Fcommonauth&response_type
    =code&client_id=<ENTER_CLIENT_ID>&scope=http%3A%2F%2Fmail.google.com&approval_prompt=force&access_type=offline
   
   Example 
            
    https://accounts.google.com/o/oauth2/auth?redirect_uri=https%3A%2F%2Flocalhost%3A9443%2Fcommonauth&response_type=code&client_id=<ENTER_CLIENT_ID>&scope=http%3A%2F%2Fmail.google.com&approval_prompt=force&access_type=offline
   
   12. Paste the updated URL into your browser.
       - Select the preferred Gmail account with which you wish to proceed.
       - Click **Allow**.
       - Obtain the authorization code using a SAML tracer on your browser.

   ![](images/image2017-11-17_18-47-47.png)

   13. To generate the access token, copy the following cURL command and replace the following place holders:
       - **<CLIENT-ID>** : Replace this with the client ID obtained in Step 10 above.
       - **<CLIENT_SECRET>** : Replace this with the client secret obtained in Step 10 above.
       - **<AUTHORIZATION_CODE>** : Replace this with the authorization code obtained in Step 12 above.
   
   
   Format
       
         curl -v -X POST --basic -u <CLIENT-ID>:<CLIENT_SECRET> -H "Content-Type: application/x-www-form-urlencoded;charset=UTF-8" -k -d "grant_type=authorization_code&code=<AUTHORIZATION_CODE>&redirect_uri=https://localhost:9443/commonauth" https://www.googleapis.com/oauth2/v3/token
       
   Example
       
         curl -v -X POST --basic -u 854665841399-l13g81ri4q98elpen1i1uhsdjulhp7ha.apps.googleusercontent.com:MK3h4fhSUT-aCTtSquMB3Vll -H "Content-Type: application/x-www-form-urlencoded;charset=UTF-8" -k -d "grant_type=authorization_code&code=4/KEDlA2KjGtib4KlyzaKzVNuDfvAmFZ10T82usT-6llY#&redirect_uri=https://localhost:9443/commonauth" https://www.googleapis.com/oauth2/v3/token
     
   Sample Response
      
         > POST /oauth2/v3/token HTTP/1.1
         > Host: www.googleapis.com
         > Authorization: Basic OTk3NDE2ODczOTUwLWY4Y2N1YnJobW1ramdkYXNkNnZkZ2tzOGxoaWExcnRhLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tOkJkNlBoY3ZVWXFrM1BhdnA4ZjBZcUQtMw==
         > User-Agent: curl/7.54.0
         > Accept: */*
         > Content-Type: application/x-www-form-urlencoded;charset=UTF-8
         > Content-Length: 127
         >
         < HTTP/1.1 200 OK
         < Cache-Control: no-cache, no-store, max-age=0, must-revalidate
         < Pragma: no-cache
         < Expires: Mon, 01 Jan 1990 00:00:00 GMT
         < Date: Wed, 10 Jan 2018 08:29:57 GMT
         < Vary: X-Origin
         < Content-Type: application/json; charset=UTF-8
         < X-Content-Type-Options: nosniff
         < X-Frame-Options: SAMEORIGIN
         < X-XSS-Protection: 1; mode=block
         < Server: GSE
         < Alt-Svc: hq=":443"; ma=2592000; quic=51303431; quic=51303339; quic=51303338; quic=51303337; quic=51303335,quic=":443"; ma=2592000; v="41,39,38,37,35"
         < Accept-Ranges: none
         < Vary: Origin,Accept-Encoding
         < Transfer-Encoding: chunked
         <
         {
          "access_token": "ya29.Gls-BbTUseE2f-Lrc9q0QtdlvIoYFTg2zkYPsXHwgob4pHAFlE66GMgJjwTHT9eHfivhVcATROzU8FaUgt0wVL1sz-7IsC2Slfpdm6i3uFcurNTFbTlABk3jKJ--",
          "token_type": "Bearer",
          "expires_in": 3600,
          "refresh_token": "1/8pMBx_lrUyitknmGzzH-yOcvoPIZ1OqhPeWvcYJOd0U"
         }
         
   Paste the updated cURL command in your terminal to generate the OAuth2 access token, token validity period, and the refresh token. 

   ![](images/image2017-11-17_19-7-38.png)

   14. Update the following configurations under the  \<AuthenticatorConfigs>  section in the  
   <IS_HOME>/repository/conf/identity/application-authentication.xml  file. 
        
        - If you need to send the content in a payload, you can introduce a property in a format <API> Payload and 
        define the value. Similarly, you can define the Form Data.FormdataforSendgridAPIisgivenasan example.
        - You can use \<API> URLParams, \<API>AuthTokenType, \<API>Failure and \<API>TokenEndpoint property formats to 
        specify the URL parameters, Authorization token type, Message to identify failure and Endpoint to get access token from refresh token respectively.
        - Value of <API> URLParams should be like; api_user=<API_USER>&api_key=<API_KEY>&data=<DATA>&list<LIST>

   |Property|Description|
   |--------|-----------|
   |**GmailClientId**	|Enter the Client ID you got in step 10.Example: 501390351749-ftjrp3ld9da4ohd1rulogejscpln646s.apps.googleusercontent.com|
   |**GmailClientSecret**|	Enter the client secret you got in step 10. Example: dj4st7_m3AclenZR1weFNo1V|
   |**SendgridAPIKey**	|This property is only required if you are using the Sengrid method. Since you are using Gmail APIs, keep the default value.|
   | **GmailRefreshToken**|	Enter the refresh token that you got as the response in step 12. Example: 1/YgNiepY107SyzJdgpynmf-eMYP4qYTPNG_L73MXfcbv|
   |**GmailEmailEndpoint**	|Enter your username of your Gmail account in place of the [userId] place holder. Example: https://www.googleapis.com/gmail/v1/users/alex@gmail.com/messages/send|
   |**SendgridEmailEndpoint**|	This property is only required if you are using the Sengrid method. Since you are using Gmail APIs, keep the default value.|
   |**accessTokenRequiredAPIs**	| Use the default value.|
   | **apiKeyHeaderRequiredAPIs**| This property is only required if you are using the Sengrid method. Since you are using Gmail APIs, keep the default value.|
   | **SendgridFormData=to**|	This property is only required if you are using the Sengrid method. Since you are using Gmail APIs, keep the default value.|
   | **SendgridURLParams**|	This property is only required if you are using the Sengrid method. Since you are using Gmail APIs, keep the default value.|
   |**GmailAuthTokenType**|	Use the default value.|
   | **GmailTokenEndpoint**|	Use the the deafult value.|
   |**SendgridAuthTokenType**|	This property is only required if you are using the Sengrid method. Since you are using Gmail APIs, keep the default value.|
    
   Sample configuration
   
     <AuthenticatorConfig name="EmailOTP" enabled="true">
        <Parameter name="GmailClientId">501390351749-ftjrp3ld9da4ohd1rulogejscpln646s.apps.googleusercontent.com</Parameter>
        <Parameter name="GmailClientSecret">dj4st7_m3AclenZR1weFNo1V</Parameter>
        <Parameter name="SendgridAPIKey">sendgridAPIKeyValue</Parameter>
        <Parameter name="GmailRefreshToken">1/YgNiepY107SyzJdgpynmf-eMYP4qYTPNG_L73MXfcbv</Parameter>
        <Parameter name="GmailEmailEndpoint">https://www.googleapis.com/gmail/v1/users/alex@gmail.com/messages/send</Parameter>
        <Parameter name="SendgridEmailEndpoint">https://api.sendgrid.com/api/mail.send.json</Parameter>
        <Parameter name="accessTokenRequiredAPIs">Gmail</Parameter>
        <Parameter name="apiKeyHeaderRequiredAPIs">Sendgrid</Parameter>
        <Parameter name="SendgridFormData">sendgridFormDataValue</Parameter>
        <Parameter name="SendgridURLParams">sendgridURLParamsValue</Parameter>
        <Parameter name="GmailAuthTokenType">Bearer</Parameter>
        <Parameter name="GmailTokenEndpoint">https://www.googleapis.com/oauth2/v3/token</Parameter>
        <Parameter name="SendgridAuthTokenType">Bearer</Parameter>
        <Parameter name="redirectToMultiOptionPageOnFailure">false</Parameter>
     </AuthenticatorConfig>
   

### Deploy the travelocity sample

Follow the steps below to deploy the travelocity.com sample application:

**Download the samples**

To be able to deploy a sample of Identity Server, you need to download it onto your machine first. 

Follow the instructions below to download a sample from GitHub.

   1. Create a folder in your local machine and navigate to it using your command line.

   2. Run the following commands.
    
    mkdir is-samples
    cd is-samples/
    git init
    git remote add -f origin https://github.com/wso2/product-is.git
    git config core.sparseCheckout true

   3. Navigate into the .git/info/ directory and list out the folders/files you want to check out using the echo 
   command below.  
    
    cd .git
    cd info
    echo "modules/samples/" >> sparse-checkout

   4. Navigate out of .git/info directory and checkout the v5.4.0 tag to update the empty repository with the remote 
   one. 
    
    cd ..
    cd ..
    git checkout -b v5.4.0 v5.4.0
 
   Access the samples by navigating to the  is-samples/modules/samples  directory.

**Deploy the sample web app**

Deploy this sample web app on a web container.

 1. Use the Apache Tomcat server to do this. If you have not downloaded Apache Tomcat already, download it from here. 
 2. Copy the .war file into the  webapps  folder. For example,  <TOMCAT_HOME>/apache-tomcat-<version>/webapps .
 3. Start the Tomcat server.

To check the sample application, navigate to http://<TOMCAT_HOST>:<TOMCAT_PORT>/travelocity.com/index.jsp on your browser.

For example, http://localhost:8080/travelocity.com/index.jsp.

***Note:***
 It is recommended that you use a hostname that is not localhost to avoid browser errors. Modify the 
/etc/hosts entry in your machine to reflect this. Note that localhost is used throughout thisdocumentation as an example, but you must modify this when configuring these authenticators or connectors with this sample application.


### Configure the Identity Provider

Follow the steps below to add an identity provider:

1. Click Add under Main > Identity > Identity Providers.
![](images/image2017-11-17_19-39-44.png)

2. Provide a suitable name for the identity provider.
![](images/image2017-11-17_19-30-35.png)

3. Expand the  EmailOTPAuthenticator Configuration under Federated Authenticators.
   - Select the Enable and Default check boxes.
   - Click Register.
![](images/image2017-11-17_19-31-57.png)

You have now added the identity provider.

### Configure the Service Provider

Follow the steps below add a service provider:

 1. Return to the Management Console home screen.

 2. Click **Add** under **Add** under **Main > Identity > Service Providers**.

 ![](images/image2017-11-17_19-38-59.png)

 3. Enter travelocity.com as the Service Provider Name.
 
 ![](images/image2017-11-17_19-41-38.png)

 4. Click **Register**.

 5. Expand **SAML2 Web SSO Configuration** under **Inbound Authentication Configuration**.

 6. Click **Configure**.
 ![](images/sp.png)

 7. Now set the configuration as follows:
    - **Issuer**: travelocity.com
    - **Assertion Consumer URL**: http://localhost:8080/travelocity.com/home.jsp
    - Select the following check-boxes: **Enable Response Signing**, **Enable Single Logout**, **Enable Attribute Profile**, and 
    **Include Attributes in the Response Always**.

 8. Click **Update** to save the changes. Now you will be sent back to the Service Providers page.

 9. Go to **Claim Configuration** and select the **http://wso2.org/claims/emailaddress** claim.
 ![](images/image2017-11-17_19-51-34.png)

 10. Go to **Local and Outbound Authentication Configuration** section.
     - Select the **Advanced configuration** radio button option.

     - Creating the first authentication step:
       - Click **Add Authentication Step**.
       - Click **Add Authenticator** that is under Local Authenticators of Step 1 to add the basic authentication as the 
       first step.
       
       Adding basic authentication as a first step ensures that the first step of authentication will be done using 
       the user's credentials that are configured with the WSO2 Identity Server

     - Creating the second authentication step:
         - Click Add Authentication Step.
         - Click Add Authenticator that is under Federated Authenticators of Step 2 to add the EmailOTP identity 
          provider you created as the second step.
            EmailOTP is a second step that adds another layer of authentication and security.

![](images/two_steps.png)

 11. Click **Update**.

 You have now added and configured the service provider.

 For more information on service provider configuration, see Configuring Single Sign-On.

### Update the email address of the user

Follow the steps given below to update the user's email address.

 1. Return to the WSO2 Identity Server Management Console home screen.
 2. Click **List** under **Add** under **Main > Identity > Users and Roles**. 
 ![](images/image2017-11-17_20-6-42.png)
     - Click Users. 
     ![](images/image2017-11-17_20-10-37.png)
     - Click User Profile under Admin. 
     ![](images/image2017-11-17_20-11-48.png)
     - Update the email address.    
     ![](images/mail_claim.png)
     - Click Update.


### Configure the user claims

Follow the steps below to map the user claims:

For more information about claims, see  Adding Claim Mapping. 

   1. Click **Add** under **Main > Identity > Claims**.
   ![](images/image2017-11-17_20-14-1.png)
      - Click Add **Local Claim**.
      
      ![](images/image2017-11-17_20-14-54.png)
       
      - Select the **Dialect** from the drop down provided and enter the required information.

      - Add the following:
          - **Claim URI** : http://wso2.org/claims/identity/emailotp_disabled
          - **Display Name**: DisableEmailOTP
          - **Description**: DisableEmailOTP
          - **Mapped Attribute (s)**: title
          - **Supported by Default**: checked
    
![](images/Email-otp-claim.png)
      - Click **Add**. 

 To disable this claim for the admin user, navigate to Users and Roles > List and click Users. Click on the User Profile link corresponding to admin account and then click Disable EmailOTP. This will disable the second factor authentication for the admin user.

### Test the sample

   1. To test the sample, go to the following URL: http://localhost:8080/travelocity.com

![](images/travelocity.jpeg)

   2. Click the link to log in with SAML from WSO2 Identity Server.

   3. The basic authentication page appears. Use your WSO2 Identity Server credentials.
    ![](images/basic.png)

   4.   You receive a token to your email account. Enter the code to authenticate. If the authentication is successful, 
   you are taken to the home page of the travelocity.com app.
   ![](images/code.png)

   ![](images/authenticated_user.png)

### UseCase Definitions.
|Value|Definitions|
|---|---|
|local|This is the default value and is based on the federated username. You must set the federated username in the local userstore . The federated username must be the same as the local username.|
|association|The federated username must be associated with the local account in advance in the end user dashboard. The local username is retrieved from the association. To associate the user, log into the  end user dashboard  and go to  Associated Account  by clicking  **View details** .|
|subjectUri|When configuring the federated authenticator, select the attribute in the subject identifier under the service provider section in UI, this is used as the username of the  EmailOTP authenticator.|
|userAttribute|The name of the  federated authenticator's user attribute. That is the local username that is contained in a federated user's attribute. When using this, add the following parameter under the \<AuthenticatorConfig name="EmailOTP" enabled="true"> section in the \<IS_HOME>/repository/conf/identity/application-authentication.xml file and put the value, <br>e.g., email and screen_name, id.<br>\<Parameter name="userAttribute">email\</Parameter><br><br>If you use OpenID Connect supported authenticators such as LinkedIn and Foursquare or in the case of multiple social login options as the first step and EmailOTP assecondstep, you need to add similar configuration for the specific authenticator in the \<IS_HOME>/repository/conf/identity/application-authentication.xml file under the \<AuthenticatorConfigs> section. <br><br>Examples:<br><br>Fourquare<br>\<AuthenticatorConfig name="Foursquare" enabled="true"><br>\<Parameter name="EmailOTP-userAttribute">http://wso2.org/foursquare/claims/email \</Parameter><br>\<Parameter name="federatedEmailAttributeKey">http://wso2.org/foursquare/claims/email \</Parameter><br>\</AuthenticatorConfig><br><br>LinkedIn<br>\<AuthenticatorConfig name="LinkedIn" enabled="true"><br>\<Parameter name="EmailOTP-userAttribute">http://wso2.org/linkedin/claims/emailAddress \</Parameter><br>\<Parameter name="federatedEmailAttributeKey">http://wso2.org/linkedin/claims/emailAddress \</Parameter><br>\</AuthenticatorConfig><br><br>Facebook<br>\<AuthenticatorConfig name="FacebookAuthenticator" enabled="true"><br>\<Parameter name="EmailOTP-userAttribute">email \</Parameter><br>\<Parameter name="federatedEmailAttributeKey">email \</Parameter><br>\</AuthenticatorConfig><br><br>Likewise, you can add the Authenticator Config for Amazon, Google, Twitter, and Instagram with the relevant values.|
