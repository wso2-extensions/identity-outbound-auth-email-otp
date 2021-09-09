Welcome to the WSO2 Identity Server (IS) EmailOTP authenticator. 

WSO2 IS is one of the best Identity Servers, which enables you to offload your identity and user entitlement management burden totally from your application. It comes with many features, supports many industry standards and most importantly it allows you to extent it according to your security requirements. This repo contains Authenticators written to work with different third party systems. 

With WSO2 IS, there are lot of provisioning capabilities available. There are 3 major concepts as Inbound, outbound provisioning and Just-In-Time provisioning. Inbound provisioning means , provisioning users and groups from an external system to IS. Outbound provisioning means , provisioning users from IS to other external systems. JIT provisioning means , once a user tries to login from an external IDP, a user can be created on the fly in IS with JIT. Repos under this account holds such components invlove in communicating with external systems.

# EMAIL OTP Service

This module provides a fully decoupled OSGI service to generate and validate EMAIL OTPs, outside
an authentication flow.

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
```
4. If notifications are managed by the Identity Server, configure the **Email template** by appending below at the end of
   the `<IS_HOME>/repository/conf/email/email-templates-admin-config.xml` file.
```xml
    <configuration type="EmailOTP" display="EmailOTP" locale="en_US" emailContentType="text/html">
    ....
    Please use this One-Time Password {{OTPCode}}
    ....
    </configuration>
```

5.Restart the server.

## REST API support
REst API support for this OSGI service can be found in the below git repository.

[identity-otp-integration-endpoints](https://github.com/wso2-extensions/identity-otp-integration-endpoints)