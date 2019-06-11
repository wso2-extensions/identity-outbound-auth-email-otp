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

public class EmailOTPAuthenticatorConstants {
    public static final String AUTHENTICATOR_NAME = "EmailOTP";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Email OTP";

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
    public static final String EMAILOTP_PAGE = "emailotpauthenticationendpoint/emailotp.jsp";
    public static final String EMAILOTP_AUTHENTICATION_ENDPOINT_URL = "EMAILOTPAuthenticationEndpointURL";
    public static final String RETRY_PARAMS = "&authFailure=true&authFailureMsg=authentication.fail.message";
    public static final String EMAIL_CLAIM = "http://wso2.org/claims/emailaddress";
    public static final String MAILING_ENDPOINT = "EmailEndpoint";
    public static final String ADMIN_EMAIL = "[userId]";
    public static final String OTP_TOKEN = "otpToken";

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

    public static final String AUTHENTICATORS = "authenticators=";
    public static final String RESEND = "resendCode";
    public static final String AUTHENTICATION = "authentication";
    public static final String SUPER_TENANT = "carbon.super";
    public static final String USER_NAME = "username";
    public static final String AUTHENTICATED_USER = "authenticatedUser";
    public static final String LOCAL_AUTHENTICATOR = "LOCAL";

    public static final String IS_EMAILOTP_MANDATORY = "EMAILOTPMandatory";
    public static final String EMAILOTP_AUTHENTICATION_ERROR_PAGE_URL = "EmailOTPAuthenticationEndpointErrorPage";
    public static final String ERROR_EMAILOTP_DISABLE = "&authFailure=true&authFailureMsg=emailotp.disable";
    public static final String SEND_OTP_DIRECTLY_DISABLE = "&authFailure=true&authFailureMsg=directly.send.otp.disable";
    public static final String ERROR_PAGE = "emailotpauthenticationendpoint/emailotpError.jsp";
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

    public static final String SCREEN_VALUE = "&screenValue=";
    public static final String SHOW_EMAIL_ADDRESS_IN_UI = "showEmailAddressInUI";
    public static final String USE_EVENT_HANDLER_BASED_EMAIL_SENDER = "useEventHandlerBasedEmailSender";
    public static final String TEMPLATE_TYPE = "TEMPLATE_TYPE";
    public static final String EVENT_NAME = "EmailOTP";
    public static final String ATTRIBUTE_EMAIL_SENT_TO = "send-to" ;

    public static final String SERVICE_PROVIDER_NAME = "serviceProviderName";
    public static final String IP_ADDRESS = "ipAddress";
}
