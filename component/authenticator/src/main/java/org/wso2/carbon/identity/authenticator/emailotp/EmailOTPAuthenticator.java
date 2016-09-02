/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.axiom.om.util.Base64;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.mgt.IdentityMgtConfigException;
import org.wso2.carbon.identity.mgt.IdentityMgtServiceException;
import org.wso2.carbon.identity.mgt.NotificationSender;
import org.wso2.carbon.identity.mgt.NotificationSendingModule;
import org.wso2.carbon.identity.mgt.config.Config;
import org.wso2.carbon.identity.mgt.config.ConfigBuilder;
import org.wso2.carbon.identity.mgt.config.ConfigType;
import org.wso2.carbon.identity.mgt.config.StorageType;
import org.wso2.carbon.identity.mgt.dto.NotificationDataDTO;
import org.wso2.carbon.identity.mgt.mail.DefaultEmailSendingModule;
import org.wso2.carbon.identity.mgt.mail.Notification;
import org.wso2.carbon.identity.mgt.mail.NotificationBuilder;
import org.wso2.carbon.identity.mgt.mail.NotificationData;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of EmailOTP
 */
public class EmailOTPAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(EmailOTPAuthenticator.class);

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside EmailOTPAuthenticator canHandle method");
        }
        return ((StringUtils.isNotEmpty(request.getParameter(EmailOTPAuthenticatorConstants.RESEND))
                && StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.CODE)))
                || StringUtils.isNotEmpty(request.getParameter(EmailOTPAuthenticatorConstants.CODE)));
    }

    /**
     * Initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            Map<String, String> emailOTPParameters = getAuthenticatorConfig().getParameterMap();
            if (!context.isRetrying() || (context.isRetrying()
                    && StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.RESEND)))
                    || (context.isRetrying()
                    && Boolean.parseBoolean(request.getParameter(EmailOTPAuthenticatorConstants.RESEND)))) {
                String username = null;
                String email = null;
                for (Integer stepMap : context.getSequenceConfig().getStepMap().keySet()) {
                    if (context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser() != null &&
                            context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedAutenticator()
                                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                        username =
                                String.valueOf(context.getSequenceConfig().getStepMap().get(stepMap).getAuthenticatedUser());
                        break;
                    }
                }
                if (StringUtils.isNotEmpty(username)) {
                    UserRealm userRealm = null;
                    String tenantDomain = MultitenantUtils.getTenantDomain(username);
                    int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                    RealmService realmService = IdentityTenantUtil.getRealmService();
                    try {
                        userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);
                    } catch (org.wso2.carbon.user.api.UserStoreException e) {
                        throw new AuthenticationFailedException("Cannot find the user realm", e);
                    }
                    username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
                    if (userRealm != null) {
                        email = userRealm.getUserStoreManager()
                                .getUserClaimValue(username, EmailOTPAuthenticatorConstants.EMAIL_CLAIM, null);
                        if (StringUtils.isEmpty(email)) {
                            log.error("Receiver's email ID can not be null.");
                            throw new AuthenticationFailedException("Receiver's email ID can not be null.");
                        } else {
                            context.setProperty(EmailOTPAuthenticatorConstants.RECEIVER_EMAIL, email);
                        }

                    }
                }
                OneTimePassword token = new OneTimePassword();
                String secret = OneTimePassword.getRandomNumber(EmailOTPAuthenticatorConstants.SECRET_KEY_LENGTH);
                String myToken = token.generateToken(secret, "" + EmailOTPAuthenticatorConstants.NUMBER_BASE
                        , EmailOTPAuthenticatorConstants.NUMBER_DIGIT);
                context.setProperty(EmailOTPAuthenticatorConstants.OTP_TOKEN, myToken);

                if (authenticatorProperties != null) {
                    if (StringUtils.isNotEmpty(myToken)) {
                        if (isSMTP(emailOTPParameters, authenticatorProperties)) {
                            sendOTP(username, myToken, email);
                        } else if (StringUtils.isNotEmpty(email)) {
                            String failureString = null;
                            if (isAccessTokenRequired(emailOTPParameters, authenticatorProperties)) {
                                String tokenResponse = sendTokenRequest(authenticatorProperties, emailOTPParameters);
                                if (StringUtils.isEmpty(tokenResponse)
                                        || tokenResponse.startsWith(EmailOTPAuthenticatorConstants.FAILED)) {
                                    log.error("Unable to get the access token");
                                    throw new AuthenticationFailedException("Unable to get the access token");
                                } else {
                                    JSONObject tokenObj = new JSONObject(tokenResponse);
                                    String accessToken =
                                            tokenObj.getString(EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN);
                                    context.getAuthenticatorProperties().put(EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN
                                            , accessToken);
                                    authenticatorProperties = context.getAuthenticatorProperties();
                                }
                            }
                            String payload = preparePayload(authenticatorProperties, emailOTPParameters, email, myToken);
                            String formData = prepareFormData(authenticatorProperties, emailOTPParameters, email, myToken);
                            String urlParams = prepareURLParams(authenticatorProperties, emailOTPParameters, email, myToken);
                            String sendCodeResponse = sendMailUsingAPIs(authenticatorProperties, emailOTPParameters,
                                    urlParams, payload, formData);
                            String api = getAPI(authenticatorProperties);
                            if (emailOTPParameters.containsKey(api + EmailOTPAuthenticatorConstants.FAILURE)) {
                                failureString = emailOTPParameters.get(api
                                        + EmailOTPAuthenticatorConstants.FAILURE);
                            }
                            if (StringUtils.isEmpty(sendCodeResponse)
                                    || sendCodeResponse.startsWith(EmailOTPAuthenticatorConstants.FAILED)
                                    || (StringUtils.isNotEmpty(failureString)
                                    && sendCodeResponse.contains(failureString))) {
                                log.error("Unable to send the code");
                                throw new AuthenticationFailedException("Unable to send the code");
                            }
                        }
                    }
                } else {
                    log.error("Error while retrieving properties. Authenticator Properties cannot be null");
                    throw new AuthenticationFailedException(
                            "Error while retrieving properties. Authenticator Properties cannot be null");
                }
            }
            if (context.isRetrying()
                    || StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.RESEND))) {
                String login = emailOTPParameters.get(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ENDPOINT_URL);
                String loginPage = "";
                if (StringUtils.isNotEmpty(login)) {
                    loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                            .replace(EmailOTPAuthenticatorConstants.LOGIN_PAGE, login);
                } else {
                    loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                            .replace(EmailOTPAuthenticatorConstants.LOGIN_PAGE, EmailOTPAuthenticatorConstants.EMAILOTP_PAGE);
                }
                String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(
                        context.getQueryParams(), context.getCallerSessionKey(),
                        context.getContextIdentifier());
                String retryParam = "";
                if (context.isRetrying()) {
                    retryParam = EmailOTPAuthenticatorConstants.RETRY_PARAMS;
                }
                try {
                    response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams))
                            + EmailOTPAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                            + EmailOTPAuthenticatorConstants.LOCAL
                            + retryParam);
                } catch (IOException e) {
                    log.error("Authentication failed: " + e.getMessage(), e);
                    throw new AuthenticationFailedException(e.getMessage(), e);
                }
            }
        } catch (UserStoreException e) {
            log.error("Cannot find the user claim for email", e);
            throw new AuthenticationFailedException("Cannot find the user claim for email " + e.getMessage(), e);
        } catch (AuthenticationFailedException e) {
            log.error(e.getMessage(), e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    /**
     * Process the response of the EmailOTP end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        if (StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.CODE))) {
            log.error("Code cannot not be null");
            throw new InvalidCredentialsException("Code cannot not be null");
        }
        if (Boolean.parseBoolean(request.getParameter(EmailOTPAuthenticatorConstants.RESEND))) {
            if (log.isDebugEnabled()) {
                log.debug("Retrying to resend the OTP");
            }
            throw new InvalidCredentialsException("Retrying to resend the OTP");
        }
        String userToken = request.getParameter(EmailOTPAuthenticatorConstants.CODE);
        String contextToken = (String) context.getProperty(EmailOTPAuthenticatorConstants.OTP_TOKEN);
        if (userToken.equals(contextToken)) {
            context.setProperty(EmailOTPAuthenticatorConstants.OTP_TOKEN, "");
            context.setProperty(EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN, "");
            String emailFromProfile = context.getProperty(EmailOTPAuthenticatorConstants.RECEIVER_EMAIL).toString();
            context.setSubject(AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(emailFromProfile));
        } else {
            log.error("Code mismatch");
            throw new AuthenticationFailedException("Code mismatch");
        }
    }

    /**
     * Send REST call
     */
    private String sendRESTCall(String url, String urlParameters, String accessToken, String formParameters
            , String payload, String httpMethod) {
        String line;
        StringBuilder responseString = new StringBuilder();
        HttpURLConnection connection = null;
        try {
            URL emailOTPEP = new URL(url + urlParameters);
            connection = (HttpURLConnection) emailOTPEP.openConnection();
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setRequestMethod(httpMethod);
            if (StringUtils.isNotEmpty(payload)) {
                if (payload.startsWith("{")) {
                    connection.setRequestProperty(EmailOTPAuthenticatorConstants.HTTP_CONTENT_TYPE
                            , payload.startsWith("{") ? EmailOTPAuthenticatorConstants.HTTP_CONTENT_TYPE_JSON
                            : EmailOTPAuthenticatorConstants.HTTP_CONTENT_TYPE_XML);
                }
            } else {
                connection.setRequestProperty(EmailOTPAuthenticatorConstants.HTTP_CONTENT_TYPE
                        , EmailOTPAuthenticatorConstants.HTTP_CONTENT_TYPE_XWFUE);
            }
            if (StringUtils.isNotEmpty(accessToken)) {
                connection.setRequestProperty(EmailOTPAuthenticatorConstants.HTTP_AUTH, accessToken);
            }
            if (httpMethod.toUpperCase().equals(EmailOTPAuthenticatorConstants.HTTP_POST)) {
                OutputStreamWriter writer = new OutputStreamWriter(connection.getOutputStream(), EmailOTPAuthenticatorConstants.CHARSET);
                if (StringUtils.isNotEmpty(payload)) {
                    writer.write(payload);
                } else if (StringUtils.isNotEmpty(formParameters)) {
                    writer.write(formParameters);
                }
                writer.close();
            }
            if (connection.getResponseCode() == 200) {
                BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                while ((line = br.readLine()) != null) {
                    responseString.append(line);
                }
                br.close();
            } else {
                return EmailOTPAuthenticatorConstants.FAILED + EmailOTPAuthenticatorConstants.REQUEST_FAILED;
            }
        } catch (ProtocolException e) {
            if (log.isDebugEnabled()) {
                log.debug(EmailOTPAuthenticatorConstants.FAILED + e.getMessage());
            }
            return EmailOTPAuthenticatorConstants.FAILED + e.getMessage();
        } catch (MalformedURLException e) {
            if (log.isDebugEnabled()) {
                log.debug(EmailOTPAuthenticatorConstants.FAILED + e.getMessage());
            }
            return EmailOTPAuthenticatorConstants.FAILED + e.getMessage();
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug(EmailOTPAuthenticatorConstants.FAILED + e.getMessage());
            }
            return EmailOTPAuthenticatorConstants.FAILED + e.getMessage();
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
        return responseString.toString();
    }

    private String preparePayload(Map<String, String> authenticatorProperties, Map<String, String> emailOTPParameters,
                                  String email, String otp) {
        String payload = null;
        String api = getAPI(authenticatorProperties);
        if (api.equals(EmailOTPAuthenticatorConstants.API_GMAIL)) {
            payload = "to:" + email + "\n" +
                    "subject:OTP Code\n" +
                    "from:" + authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL) + "\n\n" +
                    otp;
            payload = "{\"raw\":\"" + new String(Base64.encode(payload.getBytes())) + "\"}";
        } else {
            String propertyName = api + EmailOTPAuthenticatorConstants.PAYLOAD;
            payload = emailOTPParameters.get(propertyName);
            if (StringUtils.isNotEmpty(payload)) {
                String apiKey = null;
                String fromMail = authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL);
                if (emailOTPParameters.containsKey(api + EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY)) {
                    apiKey = emailOTPParameters.get(api + EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY);
                }
                payload = payload.replace(EmailOTPAuthenticatorConstants.MAIL_FROM_EMAIL, fromMail);
                payload = payload.replace(EmailOTPAuthenticatorConstants.MAIL_TO_EMAIL, email);
                payload = payload.replace(EmailOTPAuthenticatorConstants.MAIL_BODY, otp);
                payload = payload.replace(EmailOTPAuthenticatorConstants.MAIL_API_KEY, apiKey);
            }
        }
        return payload;
    }

    private String prepareURLParams(Map<String, String> authenticatorProperties, Map<String, String> emailOTPParameters,
                                    String email, String otp) {
        String propertyName = getAPI(authenticatorProperties) + EmailOTPAuthenticatorConstants.URL_PARAMS;
        return StringUtils.isNotEmpty(emailOTPParameters.get(propertyName))
                ? emailOTPParameters.get(propertyName) : null;
    }

    private String prepareFormData(Map<String, String> authenticatorProperties, Map<String, String> emailOTPParameters,
                                   String email, String otp) {
        String api = getAPI(authenticatorProperties);
        String propertyName = api + EmailOTPAuthenticatorConstants.FORM_DATA;
        String formData = emailOTPParameters.get(propertyName);
        if (StringUtils.isNotEmpty(formData)) {
            String apiKey = null;
            String fromMail = authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL);
            if (emailOTPParameters.containsKey(api + EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY)) {
                apiKey = emailOTPParameters.get(api + EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY);
            }
            formData = formData.replace(EmailOTPAuthenticatorConstants.MAIL_FROM_EMAIL, fromMail);
            formData = formData.replace(EmailOTPAuthenticatorConstants.MAIL_TO_EMAIL, email);
            formData = formData.replace(EmailOTPAuthenticatorConstants.MAIL_BODY, otp);
            formData = formData.replace(EmailOTPAuthenticatorConstants.MAIL_API_KEY, apiKey);
        }
        return formData;
    }

    private boolean isAccessTokenRequired(Map<String, String> emailOTPParameters, Map<String, String> authenticatorProperties) {
        boolean isRequired = false;
        String api = getAPI(authenticatorProperties);
        if (StringUtils.isNotEmpty(api)
                && emailOTPParameters.containsKey(EmailOTPAuthenticatorConstants.ACCESS_TOKEN_REQUIRED_APIS)) {
            isRequired = emailOTPParameters.get(EmailOTPAuthenticatorConstants.ACCESS_TOKEN_REQUIRED_APIS)
                    .contains(api);
        }
        return isRequired;
    }

    private boolean isAPIKeyHeaderRequired(Map<String, String> emailOTPParameters, Map<String, String> authenticatorProperties) {
        boolean isRequired = false;
        String api = getAPI(authenticatorProperties);
        if (StringUtils.isNotEmpty(api)
                && emailOTPParameters.containsKey(EmailOTPAuthenticatorConstants.API_KEY_HEADER_REQUIRED_APIS)) {
            isRequired = emailOTPParameters.get(EmailOTPAuthenticatorConstants.API_KEY_HEADER_REQUIRED_APIS)
                    .contains(api);
        }
        return isRequired;
    }

    private String getAPI(Map<String, String> authenticatorProperties) {
        return authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAIL_API).trim();
    }

    private String sendMailUsingAPIs(Map<String, String> authenticatorProperties, Map<String, String> emailOTPParameters, String urlParams,
                                     String payload, String formData) {
        String response = null;
        String apiKey = null;
        String endpoint = null;
        String api = getAPI(authenticatorProperties);
        if (emailOTPParameters.containsKey(api + EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY)) {
            apiKey = emailOTPParameters.get(api + EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY);
        }
        if (emailOTPParameters.containsKey(api + EmailOTPAuthenticatorConstants.MAILING_ENDPOINT)) {
            endpoint = emailOTPParameters.get(api + EmailOTPAuthenticatorConstants.MAILING_ENDPOINT);
        }
        if ((isAccessTokenRequired(emailOTPParameters, authenticatorProperties)
                && StringUtils.isEmpty(authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN)))
                || (isAPIKeyHeaderRequired(emailOTPParameters, authenticatorProperties)
                && StringUtils.isEmpty(apiKey))) {
            log.error("Required param '" + (isAccessTokenRequired(emailOTPParameters, authenticatorProperties)
                    ? EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN
                    : EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY) + "' cannot be null");
            return null;
        } else if (isAccessTokenRequired(emailOTPParameters, authenticatorProperties)
                || isAPIKeyHeaderRequired(emailOTPParameters, authenticatorProperties)) {
            String tokenType = null;
            if (emailOTPParameters.containsKey(api + EmailOTPAuthenticatorConstants.HTTP_AUTH_TOKEN_TYPE)) {
                tokenType = emailOTPParameters.get(api + EmailOTPAuthenticatorConstants.HTTP_AUTH_TOKEN_TYPE);
            }
            if (StringUtils.isNotEmpty(endpoint) && StringUtils.isNotEmpty(tokenType)) {
                if (endpoint != null) {
                    response = sendRESTCall(endpoint.replace(EmailOTPAuthenticatorConstants.ADMIN_EMAIL
                                    , authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL))
                            , StringUtils.isNotEmpty(urlParams) ? urlParams : ""
                            , tokenType + " " + (isAccessTokenRequired(emailOTPParameters, authenticatorProperties)
                                    ? authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN) : apiKey),
                            formData, payload, EmailOTPAuthenticatorConstants.HTTP_POST);
                }
            } else {
                log.error("The endpoint or access token type is empty");
                return null;
            }
        } else {
            if (StringUtils.isNotEmpty(endpoint)) {
                response = sendRESTCall(endpoint, StringUtils.isNotEmpty(urlParams) ? urlParams : "", "", "", payload,
                        EmailOTPAuthenticatorConstants.HTTP_POST);
            } else {
                log.error("The endpoint in required to send OTP via API");
                return null;
            }
        }
        return response;
    }

    private String sendTokenRequest(Map<String, String> authenticatorProperties, Map<String, String> emailOTPParameters) {
        String api = getAPI(authenticatorProperties);
        String refreshToken = null;
        String clientId = null;
        String clientSecret = null;
        if (emailOTPParameters.containsKey(api + EmailOTPAuthenticatorConstants.REFRESH_TOKEN)) {
            refreshToken = emailOTPParameters.get(api + EmailOTPAuthenticatorConstants.REFRESH_TOKEN);
        }
        if (emailOTPParameters.containsKey(api + OIDCAuthenticatorConstants.CLIENT_ID)) {
            clientId = emailOTPParameters.get(api + OIDCAuthenticatorConstants.CLIENT_ID);
        }
        if (emailOTPParameters.containsKey(api + OIDCAuthenticatorConstants.CLIENT_SECRET)) {
            clientSecret = emailOTPParameters.get(api + OIDCAuthenticatorConstants.CLIENT_SECRET);
        }
        String response = null;
        if (StringUtils.isNotEmpty(clientId) && StringUtils.isNotEmpty(clientSecret)
                && StringUtils.isNotEmpty(refreshToken)) {
            String formParams = EmailOTPAuthenticatorConstants.EMAILOTP_CLIENT_SECRET + "=" + clientSecret
                    + "&" + EmailOTPAuthenticatorConstants.EMAILOTP_GRANT_TYPE + "="
                    + EmailOTPAuthenticatorConstants.EMAILOTP_GRANT_TYPE_REFRESH_TOKEN + "&"
                    + EmailOTPAuthenticatorConstants.EMAILOTP_GRANT_TYPE_REFRESH_TOKEN + "=" + refreshToken
                    + "&" + EmailOTPAuthenticatorConstants.EMAILOTP_CLIENT_ID + "=" + clientId;
            response = sendRESTCall(getTokenEndpoint(authenticatorProperties, emailOTPParameters), "", "", formParams, ""
                    , EmailOTPAuthenticatorConstants.HTTP_POST);
        } else {
            log.error("Required params cannot be null");
            return null;
        }
        return response;
    }

    /**
     * Get EmailOTP token endpoint.
     */
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties, Map<String, String> emailOTPParameters) {
        String tokenEndpoint = null;
        String api = getAPI(authenticatorProperties);
        if (emailOTPParameters.containsKey(api + EmailOTPAuthenticatorConstants.EMAILOTP_TOKEN_ENDPOINT)) {
            tokenEndpoint = emailOTPParameters.get(api
                    + EmailOTPAuthenticatorConstants.EMAILOTP_TOKEN_ENDPOINT);
        }
        return StringUtils.isNotEmpty(tokenEndpoint) ? tokenEndpoint : null;
    }

    private void sendOTP(String username, String otp, String email) throws AuthenticationFailedException {
        System.setProperty(EmailOTPAuthenticatorConstants.AXIS2, EmailOTPAuthenticatorConstants.AXIS2_FILE);
        try {
            ConfigurationContext configurationContext =
                    ConfigurationContextFactory.createConfigurationContextFromFileSystem((String) null, (String) null);
            if (configurationContext.getAxisConfiguration().getTransportsOut()
                    .containsKey(EmailOTPAuthenticatorConstants.TRANSPORT_MAILTO)) {
                NotificationSender notificationSender = new NotificationSender();
                NotificationDataDTO notificationData = new NotificationDataDTO();
                Notification emailNotification = null;
                NotificationData emailNotificationData = new NotificationData();
                ConfigBuilder configBuilder = ConfigBuilder.getInstance();
                String tenantDomain = MultitenantUtils.getTenantDomain(username);
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                String emailTemplate;
                Config config;
                try {
                    config = configBuilder.loadConfiguration(ConfigType.EMAIL, StorageType.REGISTRY, tenantId);
                } catch (IdentityMgtConfigException e) {
                    log.error("Error occurred while loading email templates for user : " + username, e);
                    throw new AuthenticationFailedException("Error occurred while loading email templates for user : "
                            + username, e);
                }
                emailNotificationData.setTagData(EmailOTPAuthenticatorConstants.CODE, otp);
                emailNotificationData.setSendTo(email);
                if (config.getProperties().containsKey(EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME)) {
                    emailTemplate = config.getProperty(EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
                    try {
                        emailNotification = NotificationBuilder.createNotification("EMAIL", emailTemplate,
                                emailNotificationData);
                    } catch (IdentityMgtServiceException e) {
                        log.error("Error occurred while creating notification from email template : " + emailTemplate, e);
                        throw new AuthenticationFailedException("Error occurred while creating notification from email template : "
                                + emailTemplate, e);
                    }
                    notificationData.setNotificationAddress(email);
                    NotificationSendingModule module = new DefaultEmailSendingModule();
                    module.setNotificationData(notificationData);
                    module.setNotification(emailNotification);
                    notificationSender.sendNotification(module);
                    notificationData.setNotificationSent(true);
                } else {
                    throw new AuthenticationFailedException("Unable find the email template");
                }
            } else {
                throw new AuthenticationFailedException("MAILTO transport sender is not defined in axis2 configuration file");
            }
        } catch (AxisFault axisFault) {
            throw new AuthenticationFailedException("Error while getting the SMTP configuration");
        }
    }

    private boolean isSMTP(Map<String, String> emailOTPParameters, Map<String, String> authenticatorProperties) {
        String apiKey = null;
        String refreshToken = null;
        String clientId = null;
        String clientSecret = null;
        String api = getAPI(authenticatorProperties);
        String mailingEndpoint = null;
        if (emailOTPParameters.containsKey(api + EmailOTPAuthenticatorConstants.MAILING_ENDPOINT)) {
            mailingEndpoint = emailOTPParameters.get(api + EmailOTPAuthenticatorConstants.MAILING_ENDPOINT);
        }
        if (emailOTPParameters.containsKey(api + EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY)) {
            apiKey = emailOTPParameters.get(api + EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY);
        }
        if (emailOTPParameters.containsKey(api + EmailOTPAuthenticatorConstants.REFRESH_TOKEN)) {
            refreshToken = emailOTPParameters.get(api + EmailOTPAuthenticatorConstants.REFRESH_TOKEN);
        }
        if (emailOTPParameters.containsKey(api + OIDCAuthenticatorConstants.CLIENT_ID)) {
            clientId = emailOTPParameters.get(api + OIDCAuthenticatorConstants.CLIENT_ID);
        }
        if (emailOTPParameters.containsKey(api + OIDCAuthenticatorConstants.CLIENT_SECRET)) {
            clientSecret = emailOTPParameters.get(api + OIDCAuthenticatorConstants.CLIENT_SECRET);
        }
        String email = authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL);
        return StringUtils.isEmpty(email) || StringUtils.isEmpty(api) || StringUtils.isEmpty(mailingEndpoint)
                || (!isAccessTokenRequired(emailOTPParameters, authenticatorProperties) && StringUtils.isEmpty(apiKey))
                || (isAccessTokenRequired(emailOTPParameters, authenticatorProperties)
                && (StringUtils.isEmpty(refreshToken) || StringUtils.isEmpty(clientId)
                || StringUtils.isEmpty(clientSecret)));
    }

    /**
     * Check ID token in EmailOTP OAuth.
     */
    @Override
    protected boolean requiredIDToken(Map<String, String> authenticatorProperties) {
        return false;
    }

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return EmailOTPAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
    }

    /**
     * Get Configuration Properties
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<Property>();
        Property emailAPI = new Property();
        emailAPI.setName(EmailOTPAuthenticatorConstants.EMAIL_API);
        emailAPI.setDisplayName("Email API");
        emailAPI.setDescription("Enter API to send OTP (E.g: Gmail, Sendgrid etc)");
        emailAPI.setDisplayOrder(0);
        configProperties.add(emailAPI);

        Property email = new Property();
        email.setName(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL);
        email.setDisplayName("Email");
        email.setDescription("Email address of the sender");
        email.setDisplayOrder(1);
        configProperties.add(email);

        return configProperties;
    }
}