/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.emailotp;

/**
 * Class with the email authenticator constants.
 */
public class EmailOTPAuthenticatorConstants {

    public static final String AUTHENTICATOR_NAME = "EmailOTP";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Email OTP";
    public static final String IS_IDF_INITIATED_FROM_AUTHENTICATOR = "isIdfInitiatedFromAuthenticator";
    public static final String IDF_HANDLER_NAME = "IdentifierExecutor";
    public static final String ALGORITHM_NAME = "SHA1PRNG";
    public static final String ALGORITHM_HMAC = "HmacSHA1";
    public static final String ALGORITHM_HMAC_SHA = "HMAC-SHA-1";
    public static final int SECRET_KEY_LENGTH = 5;
    public static final int NUMBER_BASE = 2;
    public static final int NUMBER_DIGIT = 6;
    public static final String EMAIL_API = "EmailAPI";
    public static final String ACCESS_TOKEN_REQUIRED_APIS = "accessTokenRequiredAPIs";
    public static final String API_KEY_HEADER_REQUIRED_APIS = "apiKeyHeaderRequiredAPIs";
    public static final String API_GMAIL = "Gmail";
    public static final String API_SENDGRID = "Sendgrid";
    public static final String CLIENT_ID = "ClientId";
    public static final String CLIENT_SECRET = "ClientSecret";
    public static final String CODE = "OTPCode";
    public static final String EMAILOTP_TOKEN_ENDPOINT = "TokenEndpoint";
    public static final String REFRESH_TOKEN = "RefreshToken";
    public static final String EMAILOTP_CLIENT_ID = "client_id";
    public static final String EMAILOTP_CLIENT_SECRET = "client_secret";
    public static final String EMAILOTP_GRANT_TYPE = "grant_type";
    public static final String EMAILOTP_GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
    public static final String EMAILOTP_ACCESS_TOKEN = "access_token";
    public static final String EMAILOTP_EMAIL = "Email";
    public static final String EMAILOTP_API_KEY = "APIKey";
    public static final String RECEIVER_EMAIL = "emilFromProfile";
    public static final String PAYLOAD = "Payload";
    public static final String FORM_DATA = "FormData";
    public static final String URL_PARAMS = "URLParams";
    public static final String MAIL_FROM_EMAIL = "<FROM_EMAIL>";
    public static final String MAIL_TO_EMAIL = "<TO_EMAIL>";
    public static final String MAIL_BODY = "<BODY>";
    public static final String MAIL_API_KEY = "<API_KEY>";
    public static final String LOGIN_PAGE = "authenticationendpoint/login.do";
    public static final String EMAIL_ADDRESS_CAPTURE_PAGE = "authenticationendpoint/email_capture.do";
    public static final String EMAILOTP_PAGE = "authenticationendpoint/email_otp.do";
    public static final String ERROR_PAGE = "authenticationendpoint/email_otp_error.do";
    public static final String EMAILOTP_AUTHENTICATION_ENDPOINT_URL = "EMAILOTPAuthenticationEndpointURL";
    public static final String RETRY_PARAMS = "&authFailure=true&authFailureMsg=authentication.fail.message";
    public static final String EMAIL_CLAIM = "http://wso2.org/claims/emailaddress";
    public static final String MAILING_ENDPOINT = "EmailEndpoint";
    public static final String ADMIN_EMAIL = "[userId]";
    public static final String OTP_TOKEN = "otpToken";
    public static final String OTP_BACKUP_CODES_CLAIM = "http://wso2.org/claims/otpbackupcodes";
    public static final String BACKUP_CODES_SEPARATOR = ",";
    public static final String AXIS2 = "axis2.xml";
    public static final String AXIS2_FILE = "repository/conf/axis2/axis2.xml";
    public static final String TRANSPORT_MAILTO = "mailto";
    public static final String HTTP_POST = "POST";
    public static final String HTTP_CONTENT_TYPE = "Content-Type";
    public static final String HTTP_CONTENT_TYPE_XWFUE = "application/x-www-form-urlencoded";
    public static final String HTTP_CONTENT_TYPE_JSON = "application/json";
    public static final String HTTP_CONTENT_TYPE_XML = "application/xml";
    public static final String HTTP_AUTH = "Authorization";
    public static final String HTTP_AUTH_TOKEN_TYPE = "AuthTokenType";
    public static final String CHARSET = "UTF-8";
    public static final String REQUEST_FAILED = "Request to the API is failed";
    public static final String FAILED = "Failed: ";
    public static final String FAILURE = "Failure";
    public static final String EMAIL_UPDATE_FAILURE = "emailUpdateFailed";
    public static final String AUTHENTICATORS = "authenticators=";
    public static final String RESEND = "resendCode";
    public static final String AUTHENTICATION = "authentication";
    public static final String SUPER_TENANT = "carbon.super";
    public static final String USER_NAME = "username";
    public static final String AUTHENTICATED_USER = "authenticatedUser";
    public static final String LOCAL_AUTHENTICATOR = "LOCAL";
    public static final String REQUESTED_USER_EMAIL = "requestedEmail";
    public static final String PROFILE_UPDATE_FAILURE_REASON = "profileUpdateFailureReason";
    public static final String ERROR_MESSAGE_DETAILS = "&authFailureInfo=";
    public static final String IS_EMAILOTP_MANDATORY = "EMAILOTPMandatory";
    public static final String EMAILOTP_AUTHENTICATION_ERROR_PAGE_URL = "EmailOTPAuthenticationEndpointErrorPage";
    public static final String ERROR_EMAILOTP_DISABLE = "&authFailure=true&authFailureMsg=emailotp.disable";
    public static final String SEND_OTP_DIRECTLY_DISABLE = "&authFailure=true&authFailureMsg=directly.send.otp.disable";
    public static final String BASIC = "basic";
    public static final String FEDERETOR = "federator";
    public static final String SEND_OTP_TO_FEDERATED_EMAIL_ATTRIBUTE = "sendOTPToFederatedEmailAttribute";
    public static final String FEDERATED_EMAIL_ATTRIBUTE_KEY = "federatedEmailAttributeKey";
    public static final String USE_CASE = "usecase";
    public static final String USER_EMAILOTP_DISABLED_CLAIM_URI = "http://wso2.org/claims/identity/emailotp_disabled";
    public static final String IS_ENABLE_EMAIL_VALUE_UPDATE = "CaptureAndUpdateEmailAddress";
    public static final String EMAIL_ADDRESS = "EMAIL_ADDRESS";
    public static final String IS_EMAILOTP_ENABLE_BY_USER = "EmailOTPEnableByUserClaim";
    public static final String EMAIL_ADDRESS_REQ_PAGE = "EmailAddressRequestPage";
    public static final String CODE_MISMATCH = "codeMismatch";
    public static final String BACKUP_CODE = "BackupCode";
    public static final String PASS_SP_NAME_TO_EVENT = "passSPNameToEvent";
    public static final String SCREEN_VALUE = "&screenValue=";
    public static final String SHOW_EMAIL_ADDRESS_IN_UI = "showEmailAddressInUI";
    public static final String EMAIL_ADDRESS_REGEX = "emailAddressRegex";
    public static final String USE_EVENT_HANDLER_BASED_EMAIL_SENDER = "useEventHandlerBasedEmailSender";
    public static final String TEMPLATE_TYPE = "TEMPLATE_TYPE";
    public static final String EVENT_NAME = "EmailOTP";
    public static final String ATTRIBUTE_EMAIL_SENT_TO = "send-to";
    public static final String OTP_GENERATED_TIME = "tokenGeneratedTime";
    public static final String TOKEN_EXPIRE_TIME_IN_MILIS = "tokenExpirationTime";
    public static final String OTP_EXPIRE_TIME_DEFAULT = "300000";
    public static final String OTP_EXPIRED = "isOTPExpired";
    public static final String DISABLE_OTP_RESEND_ON_FAILURE = "disableOTPResendOnFailure";
    public static final String SERVICE_PROVIDER_NAME = "serviceProviderName";
    public static final String IP_ADDRESS = "ipAddress";
    public static final String USER_AGENT = "user-agent";
    public static final String X_FORWARDED_FOR = "x-forwarded-for";
    public static final String STATUS_SUCCESS = "success";
    public static final String STATUS_OTP_EXPIRED = "otp-expired";
    public static final String STATUS_CODE_MISMATCH = "code-mismatch";
    public static final String TRUE = "true";
    // Account lock related constants.
    public static final String EMAIL_OTP_FAILED_ATTEMPTS_CLAIM =
            "http://wso2.org/claims/identity/failedEmailOtpAttempts";
    public static final String FAILED_LOGIN_LOCKOUT_COUNT_CLAIM = "http://wso2.org/claims/identity/" +
            "failedLoginLockoutCount";
    public static final String ACCOUNT_LOCKED_CLAIM = "http://wso2.org/claims/identity/accountLocked";
    public static final String ACCOUNT_UNLOCK_TIME_CLAIM = "http://wso2.org/claims/identity/unlockTime";
    public static final String ACCOUNT_LOCKED_REASON_CLAIM_URI = "http://wso2.org/claims/identity/lockedReason";
    public static final String SHOW_AUTH_FAILURE_REASON = "showAuthFailureReason";
    public static final String ENABLE_ACCOUNT_LOCKING_FOR_FAILED_ATTEMPTS = "EnableAccountLockingForFailedAttempts";
    public static final String PROPERTY_LOGIN_FAIL_TIMEOUT_RATIO = "account.lock.handler.login.fail.timeout.ratio";
    public static final String PROPERTY_ACCOUNT_LOCK_ON_FAILURE = "account.lock.handler.enable";
    public static final String PROPERTY_ACCOUNT_LOCK_ON_FAILURE_MAX = "account.lock.handler.On.Failure.Max.Attempts";
    public static final String PROPERTY_ACCOUNT_LOCK_TIME = "account.lock.handler.Time";
    public static final String ERROR_USER_ACCOUNT_LOCKED = "&authFailure=true&authFailureMsg=user.account.locked";
    public static final String ADMIN_INITIATED = "AdminInitiated";
    public static final String MAX_EMAIL_OTP_ATTEMPTS_EXCEEDED = "MAX_EMAIL_OTP_ATTEMPTS_EXCEEDED";
    public static final String OTP_IS_OPTIONAL_AND_USER_DISABLED_EMAIL_OTP = "otpIsOptionalAndUserDisabledEmailOTP";
    public static final String OTP_IS_OPTIONAL_WITHOUT_FEDERATED_EMAIL = "otpIsOptionalWithoutFederatedEmail";
    public static final String OTP_OPTIONAL_WITHOUT_SEND_OTP_TO_FEDERATED_EMAIL =
            "otpOptionalWithoutSendOTPToFederatedEmail";

    private EmailOTPAuthenticatorConstants() {

    }

}
