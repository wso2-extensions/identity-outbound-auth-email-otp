# EMAIL OTP Service

This module provides a fully decoupled OSGI service to generate and validate EMAIL OTPs, outside
the authentication flow.

## Deployment instructions
1. Build the repository using `mvn clean install`.
2. Copy the `org.wso2.carbon.extension.identity.emailotp.common-<VERSION>.jar` to the
   `<IS_HOME>/repository/components/dropins` directory.
3. Add the below configurations to the `<IS_HOME>/repository/conf/deployment.toml` file.
```properties
[[event_handler]]
name = "emailOtp"
properties.enabled = true
properties.tokenLength = 6
properties.triggerNotification = true
properties.alphanumericToken = true
# OTP validation failure reason will be sent in the response.
properties.showValidationFailureReason = false
properties.tokenValidityPeriod = 120
# Same valid OTP will be resent, if issued within the interval.
# Set '0' to always send a new OTP.
# Should be less than the 'tokenValidityPeriod' value.
properties.tokenRenewalInterval= 60
# Throttle OTP generation requests from the same user Id.
# Set '0' for no throttling.
properties.resendThrottleInterval = 30
# Lock the account after reaching the maximum number of failed login attempts.
properties.lockAccountOnFailedAttempts = true
```

   **NOTE:** If `properties.lockAccountOnFailedAttempts` is set to `true`, at tenant level it is required to enable
   the account lock capability and configure other properties such as unlock time duration.
   For more details, refer to the documentation: https://is.docs.wso2.com/en/5.11.0/learn/account-locking-by-failed-login-attempts/#configuring-wso2-is-for-account-locking

4. If notifications are managed by the Identity Server, configure the **Email template** by appending below at the end of
   the `<IS_HOME>/repository/conf/email/email-templates-admin-config.xml` file.
```xml
    <configuration type="EmailOTP" display="EmailOTP" locale="en_US" emailContentType="text/html">
    ....
    Please use this One-Time Password {{OTPCode}}
    ....
    </configuration>
```

5. Restart the server.