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

import org.apache.axiom.om.util.Base64;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticator;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.emailotp.exception.EmailOTPException;
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
import org.wso2.carbon.user.api.UserStoreException;
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

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
        // if the logout request comes, then no need to go through and complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.CODE))) {
            // if the request comes with code, it will go through this flow.
            initiateAuthenticationRequest(request, response, context);
            if (context.getProperty(EmailOTPAuthenticatorConstants.AUTHENTICATION)
                    .equals(EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME)) {
                // if the request comes with authentication is EmailOTP, it will go through this flow.
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                // if the request comes with authentication is basic, complete the flow.
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
        } else {
            return super.process(request, response, context);
        }
    }

    /**
     * Initiate the authentication request
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        try {
            boolean isEmailOTPMandatory;
            boolean sendOtpToFederatedEmail;
            Object propertiesFromLocal = null;
            AuthenticatedUser authenticatedUser;
            Map<String, String> emailOTPParameters = getAuthenticatorConfig().getParameterMap();
            String tenantDomain = context.getTenantDomain();
            context.setProperty(EmailOTPAuthenticatorConstants.AUTHENTICATION,
                    EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
            if (!tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
                IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, getName(), tenantDomain);
                propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
            }
            if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
                isEmailOTPMandatory = Boolean.parseBoolean(emailOTPParameters
                        .get(EmailOTPAuthenticatorConstants.IS_EMAILOTP_MANDATORY));
                sendOtpToFederatedEmail = Boolean.parseBoolean(emailOTPParameters
                        .get(EmailOTPAuthenticatorConstants.SEND_OTP_TO_FEDERATED_EMAIL_ATTRIBUTE));

            } else {
                isEmailOTPMandatory = Boolean.parseBoolean(String.valueOf(context.getProperty
                        (EmailOTPAuthenticatorConstants.IS_EMAILOTP_MANDATORY)));
                sendOtpToFederatedEmail = Boolean.parseBoolean(String.valueOf(context.getProperty
                        (EmailOTPAuthenticatorConstants.SEND_OTP_TO_FEDERATED_EMAIL_ATTRIBUTE)));
            }
            FederatedAuthenticator federatedAuthenticator = new FederatedAuthenticator();
            federatedAuthenticator.getUsernameFromFirstStep(context);
            String username = String.valueOf(context.getProperty(EmailOTPAuthenticatorConstants.USER_NAME));
            authenticatedUser = (AuthenticatedUser) context.getProperty
                    (EmailOTPAuthenticatorConstants.AUTHENTICATED_USER);
            // find the authenticated user.
            if (authenticatedUser == null) {
                throw new AuthenticationFailedException
                        ("Authentication failed!. Cannot proceed further without identifying the user");
            }
            boolean isUserExistence = federatedAuthenticator.isExistUserInUserStore(username);
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(
                    context.getQueryParams(), context.getCallerSessionKey(),
                    context.getContextIdentifier());
            String retryParam = "";
            if (isEmailOTPMandatory) {
                processEmailOTPMandatory(context, request, response, isUserExistence, username, queryParams,
                        retryParam, emailOTPParameters, sendOtpToFederatedEmail, federatedAuthenticator);
            } else if (isUserExistence && EmailOTPUtils.isEmailOTPEnableForLocalUser(username, context)) {
                String email = EmailOTPUtils.getEmailValueForUsername(username, context);
                processEmailOTPFlow(request, response, email, username, queryParams, retryParam, context);
            } else {
                processFirstStepOnly(federatedAuthenticator, authenticatedUser, context);
            }
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException("Authentication Failed :" + e.getMessage(), e);
        } catch (EmailOTPException e) {
            throw new AuthenticationFailedException("Failed to get the parameters from authentication xml fie", e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to get the user from user store " + e.getMessage(), e);
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
     * Checks whether email API or via SMTP protocol is used to send OTP to email
     *
     * @param context                 the authentication context
     * @param emailOTPParameters      EmailOTP Parameters
     * @param authenticatorProperties the authenticator properties
     * @param email                   the email value to send OTP
     * @param username                username according to the use case
     * @param myToken                 the token
     * @throws AuthenticationFailedException
     */
    private void checkEmailOTPBehaviour(AuthenticationContext context, Map<String, String> emailOTPParameters,
                                        Map<String, String> authenticatorProperties, String email, String username,
                                        String myToken) throws AuthenticationFailedException {
        if (isSMTP(authenticatorProperties, emailOTPParameters, context)) {
            sendOTP(username, myToken, email);
        } else if (StringUtils.isNotEmpty(email)) {
            authenticatorProperties = getAuthenticatorPropertiesWithTokenResponse(context, emailOTPParameters,
                    authenticatorProperties);
            String payload = preparePayload(context, authenticatorProperties, emailOTPParameters, email, myToken);
            String formData = prepareFormData(context, authenticatorProperties, emailOTPParameters, email, myToken);
            String urlParams = prepareURLParams(context, authenticatorProperties, emailOTPParameters, email, myToken);
            String sendCodeResponse = sendMailUsingAPIs(context, authenticatorProperties, emailOTPParameters, urlParams,
                    payload, formData);
            String api = getAPI(authenticatorProperties);
            String failureString = EmailOTPUtils.getFailureString(context, emailOTPParameters, getName(), api);
            if (StringUtils.isEmpty(sendCodeResponse)
                    || sendCodeResponse.startsWith(EmailOTPAuthenticatorConstants.FAILED)
                    || (StringUtils.isNotEmpty(failureString) && sendCodeResponse.contains(failureString))) {
                throw new AuthenticationFailedException("Unable to send the code");
            }
        }
    }

    /**
     * Get new authenticator properties with the accessToken response if emailApi used to send OTP
     *
     * @param context                 the authentication context
     * @param emailOTPParameters      EmailOTP Parameters
     * @param authenticatorProperties the authenticator properties
     * @return authenticatorProperties by appending the token response
     * @throws AuthenticationFailedException
     */
    private Map<String, String> getAuthenticatorPropertiesWithTokenResponse(AuthenticationContext context,
                                                                            Map<String, String> emailOTPParameters,
                                                                            Map<String, String> authenticatorProperties)
            throws AuthenticationFailedException {
        if (isAccessTokenRequired(context, emailOTPParameters, authenticatorProperties)) {
            String tokenResponse = sendTokenRequest(context, authenticatorProperties, emailOTPParameters);
            if (StringUtils.isEmpty(tokenResponse) || tokenResponse.startsWith(EmailOTPAuthenticatorConstants.FAILED)) {
                throw new AuthenticationFailedException("Unable to get the access token");
            } else {
                JSONObject tokenObj = new JSONObject(tokenResponse);
                String accessToken = tokenObj.getString(EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN);
                context.getAuthenticatorProperties().put(EmailOTPAuthenticatorConstants.
                        EMAILOTP_ACCESS_TOKEN, accessToken);
                authenticatorProperties = context.getAuthenticatorProperties();
            }
        }
        return authenticatorProperties;
    }

    /**
     * Get federated authenticator key of email attribute (email or specific claim dialect for email attribute)
     *
     * @param context                the authentication context
     * @param authenticatorName      the authenticator name
     * @param federatedAuthenticator the federatedAuthenticator
     * @return the key of federatedEmailAttribute
     * @throws AuthenticationFailedException
     */
    private String getFederatedEmailAttributeKey(AuthenticationContext context, String authenticatorName,
                                                 FederatedAuthenticator federatedAuthenticator)
            throws AuthenticationFailedException {
        String federatedEmailAttributeKey = null;
        Map<String, String> parametersMap;
        Object propertiesFromLocal = null;
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, authenticatorName, tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            parametersMap = federatedAuthenticator.getAuthenticatorConfig(authenticatorName);
            if (parametersMap != null) {
                federatedEmailAttributeKey = parametersMap.get
                        (EmailOTPAuthenticatorConstants.FEDERATED_EMAIL_ATTRIBUTE_KEY);
            }
        } else {
            federatedEmailAttributeKey = String.valueOf(context.getProperty
                    (EmailOTPAuthenticatorConstants.FEDERATED_EMAIL_ATTRIBUTE_KEY));
        }
        return federatedEmailAttributeKey;
    }

    /**
     * Check EmailOTP Mandatory case
     */
    private void processEmailOTPMandatory(AuthenticationContext context, HttpServletRequest request,
                                          HttpServletResponse response, boolean isUserExistence, String username,
                                          String queryParams, String retryParam, Map<String, String> emailOTPParameters,
                                          boolean sendOtpToFederatedEmail, FederatedAuthenticator federatedAuthenticator)
            throws EmailOTPException, AuthenticationFailedException {
        String errorPage = EmailOTPUtils.getErrorPage(context, emailOTPParameters, getName());
        if (isUserExistence) {
            boolean isEmailOTPEnabledByUser = EmailOTPUtils.isEmailOTPEnableForLocalUser(username, context);
            checkEmailEnableByUser(context, request, response, username, isEmailOTPEnabledByUser,
                    queryParams, retryParam, errorPage);
        } else {
            checkSendOtpDirectlyEnable(context, request, response, username, queryParams, retryParam,
                    sendOtpToFederatedEmail, errorPage, federatedAuthenticator);
        }
    }

    /**
     * Check whether the user has email value in user's profile
     */
    private void checkEmailEnableByUser(AuthenticationContext context, HttpServletRequest request,
                                        HttpServletResponse response, String username, boolean isEmailOTPEnabledByUser,
                                        String queryParams, String retryParam, String errorPage)
            throws AuthenticationFailedException {
        try {
            if (isEmailOTPEnabledByUser) {
                // Email OTP authentication is mandatory and user have Email value in user's profile.
                String email = EmailOTPUtils.getEmailValueForUsername(username, context);
                processEmailOTPFlow(request, response, email, username, queryParams, retryParam, context);
            } else {
                // Email OTP authentication is mandatory and user doesn't have Email value in user's profile.
                // Cannot proceed further without EmailOTP authentication.
                retryParam = EmailOTPAuthenticatorConstants.ERROR_EMAILOTP_DISABLE;
                redirectToErrorPage(response, errorPage, queryParams, retryParam);
            }
        } catch (AuthenticationFailedException | EmailOTPException e) {
            throw new AuthenticationFailedException("Failed to process EmailOTP flow ", e);
        }
    }

    /**
     * In EmailOTP mandatory case, If user not found in the directory then send otp directly to federated email
     */
    private void checkSendOtpDirectlyEnable(AuthenticationContext context, HttpServletRequest request,
                                            HttpServletResponse response, String username, String queryParams,
                                            String retryParam, boolean sendOtpToFederatedEmail, String errorPage,
                                            FederatedAuthenticator federatedAuthenticator)
            throws AuthenticationFailedException {
        try {
            String federatedEmailAttributeKey;
            String email = null;
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
            String previousStepAuthenticator = stepConfig.getAuthenticatedAutenticator().getName();
            StepConfig currentStep = context.getSequenceConfig().getStepMap().get(context.getCurrentStep());
            String currentStepAuthenticator = currentStep.getAuthenticatorList().iterator().next().getName();
            if (sendOtpToFederatedEmail) {
                federatedEmailAttributeKey = getFederatedEmailAttributeKey(context, previousStepAuthenticator,
                        federatedAuthenticator);
                if (StringUtils.isEmpty(federatedEmailAttributeKey)) {
                    federatedEmailAttributeKey = getFederatedEmailAttributeKey(context, currentStepAuthenticator,
                            federatedAuthenticator);
                }
                // Email OTP authentication is mandatory and user doesn't exist in user store,then send the OTP to
                // the email which is got from the claim set.
                Map<ClaimMapping, String> userAttributes = context.getCurrentAuthenticatedIdPs().values().
                        iterator().next().getUser().getUserAttributes();
                for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                    String key = String.valueOf(entry.getKey().getLocalClaim().getClaimUri());
                    String value = entry.getValue();
                    if (key.equals(federatedEmailAttributeKey)) {
                        email = String.valueOf(value);
                        context.setProperty(EmailOTPAuthenticatorConstants.RECEIVER_EMAIL, email);
                        processEmailOTPFlow(request, response, email, username, queryParams, retryParam, context);
                        break;
                    }
                }
                if (StringUtils.isEmpty(email)) {
                    throw new AuthenticationFailedException("There is no email claim to send otp");
                }
            } else {
                retryParam = EmailOTPAuthenticatorConstants.SEND_OTP_DIRECTLY_DISABLE;
                redirectToErrorPage(response, errorPage, queryParams, retryParam);
            }
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException(" Failed to process EmailOTP flow ", e);
        }
    }

    /**
     * In EmailOTP optional case, If uer not found or email claim doesn't enable then process the first step only
     */
    private void processFirstStepOnly(FederatedAuthenticator federatedAuthenticator, AuthenticatedUser authenticatedUser,
                                      AuthenticationContext context) {
        //the authentication flow happens with basic authentication (First step only).
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        if (stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof
                LocalApplicationAuthenticator) {
            federatedAuthenticator.updateLocalAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(EmailOTPAuthenticatorConstants.AUTHENTICATION, EmailOTPAuthenticatorConstants.BASIC);
        } else {
            federatedAuthenticator.updateAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(EmailOTPAuthenticatorConstants.AUTHENTICATION, EmailOTPAuthenticatorConstants.FEDERETOR);
        }
    }

    /**
     * To redirect flow to error page with specific condition
     */
    private void redirectToErrorPage(HttpServletResponse response, String errorPage, String queryParams,
                                     String retryParam) throws AuthenticationFailedException {
        try {
            if (StringUtils.isEmpty(errorPage)) {
                errorPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                        .replace(EmailOTPAuthenticatorConstants.LOGIN_PAGE, EmailOTPAuthenticatorConstants.ERROR_PAGE);
                if (log.isDebugEnabled()) {
                    log.debug("Default authentication endpoint context is used");
                }
            }
            response.sendRedirect(errorPage + ("?" + queryParams) + EmailOTPAuthenticatorConstants.AUTHENTICATORS
                    + getName() + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Authentication Failed " + e.getMessage(), e);
        }
    }

    /**
     * Process the EmailOTP Flow
     *
     * @param request     the request
     * @param response    response
     * @param email       value of the email to send otp
     * @param username    the username
     * @param queryParams the queryParams
     * @param retryParam  the retryParams
     * @param context     the authentication context
     * @throws AuthenticationFailedException
     */
    private void processEmailOTPFlow(HttpServletRequest request, HttpServletResponse response, String email,
                                     String username, String queryParams, String retryParam,
                                     AuthenticationContext context) throws AuthenticationFailedException {
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        Map<String, String> emailOTPParameters = getAuthenticatorConfig().getParameterMap();
        try {
            if (!context.isRetrying() || (context.isRetrying()
                    && StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.RESEND)))
                    || (context.isRetrying()
                    && Boolean.parseBoolean(request.getParameter(EmailOTPAuthenticatorConstants.RESEND)))) {

                OneTimePassword token = new OneTimePassword();
                String secret = OneTimePassword.getRandomNumber(EmailOTPAuthenticatorConstants.SECRET_KEY_LENGTH);
                String myToken = token.generateToken(secret, "" + EmailOTPAuthenticatorConstants.NUMBER_BASE
                        , EmailOTPAuthenticatorConstants.NUMBER_DIGIT);
                context.setProperty(EmailOTPAuthenticatorConstants.OTP_TOKEN, myToken);
                if (authenticatorProperties != null) {
                    if (StringUtils.isNotEmpty(myToken)) {
                        checkEmailOTPBehaviour(context, emailOTPParameters, authenticatorProperties, email, username,
                                myToken);
                    }
                } else {
                    throw new AuthenticationFailedException(
                            "Error while retrieving properties. Authenticator Properties cannot be null");
                }
            }
            if (context.isRetrying()
                    || StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.RESEND))) {
                // Full url of the login page
                String loginPage = EmailOTPUtils.getLoginPage(context, emailOTPParameters, getName());
                if (StringUtils.isEmpty(loginPage)) {
                    loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL().replace
                            (EmailOTPAuthenticatorConstants.LOGIN_PAGE, EmailOTPAuthenticatorConstants.EMAILOTP_PAGE);
                }
                if (context.isRetrying()) {
                    retryParam = EmailOTPAuthenticatorConstants.RETRY_PARAMS;
                }
                try {
                    response.sendRedirect(loginPage + ("?" + queryParams)
                            + EmailOTPAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                            + EmailOTPAuthenticatorConstants.LOCAL
                            + retryParam);
                } catch (IOException e) {
                    throw new AuthenticationFailedException(e.getMessage(), e);
                }
            }
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
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

    private String preparePayload(AuthenticationContext context, Map<String, String> authenticatorProperties,
                                  Map<String, String> emailOTPParameters, String email, String otp)
            throws AuthenticationFailedException {
        String payload = null;
        String api = getAPI(authenticatorProperties);
        if (api.equals(EmailOTPAuthenticatorConstants.API_GMAIL)) {
            payload = "to:" + email + "\n" +
                    "subject:OTP Code\n" +
                    "from:" + authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL) + "\n\n" +
                    otp;
            payload = "{\"raw\":\"" + new String(Base64.encode(payload.getBytes())) + "\"}";
        } else {
            payload = EmailOTPUtils.getPreparePayload(context, emailOTPParameters, getName(), api);
            if (StringUtils.isNotEmpty(payload)) {
                String fromMail = authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL);
                String apiKey = EmailOTPUtils.getApiKey(context, emailOTPParameters, getName(), api);
                payload = payload.replace(EmailOTPAuthenticatorConstants.MAIL_FROM_EMAIL, fromMail);
                payload = payload.replace(EmailOTPAuthenticatorConstants.MAIL_TO_EMAIL, email);
                payload = payload.replace(EmailOTPAuthenticatorConstants.MAIL_BODY, otp);
                payload = payload.replace(EmailOTPAuthenticatorConstants.MAIL_API_KEY, apiKey);
            }
        }
        return payload;
    }

    private String prepareURLParams(AuthenticationContext context, Map<String, String> authenticatorProperties,
                                    Map<String, String> emailOTPParameters, String email, String otp)
            throws AuthenticationFailedException {
        String api = getAPI(authenticatorProperties);
        String urlParams = EmailOTPUtils.getPrepareURLParams(context, emailOTPParameters, getName(), api);
        return StringUtils.isNotEmpty(urlParams) ? urlParams : null;
    }

    private String prepareFormData(AuthenticationContext context, Map<String, String> authenticatorProperties,
                                   Map<String, String> emailOTPParameters, String email, String otp)
            throws AuthenticationFailedException {
        String api = getAPI(authenticatorProperties);
        String formData = EmailOTPUtils.getPrepareFormData(context, emailOTPParameters, getName(), api);
        if (StringUtils.isNotEmpty(formData)) {
            String fromMail = authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL);
            String apiKey = EmailOTPUtils.getApiKey(context, emailOTPParameters, getName(), api);
            formData = formData.replace(EmailOTPAuthenticatorConstants.MAIL_FROM_EMAIL, fromMail);
            formData = formData.replace(EmailOTPAuthenticatorConstants.MAIL_TO_EMAIL, email);
            formData = formData.replace(EmailOTPAuthenticatorConstants.MAIL_BODY, otp);
            formData = formData.replace(EmailOTPAuthenticatorConstants.MAIL_API_KEY, apiKey);
        }
        return formData;
    }

    private boolean isAccessTokenRequired(AuthenticationContext context, Map<String, String> emailOTPParameters,
                                          Map<String, String> authenticatorProperties)
            throws AuthenticationFailedException {
        boolean isRequired = false;
        Object propertiesFromLocal = null;
        String api = getAPI(authenticatorProperties);
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, getName(), tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            if (StringUtils.isNotEmpty(api)
                    && emailOTPParameters.containsKey(EmailOTPAuthenticatorConstants.ACCESS_TOKEN_REQUIRED_APIS)) {
                isRequired = emailOTPParameters.get(EmailOTPAuthenticatorConstants.ACCESS_TOKEN_REQUIRED_APIS)
                        .contains(api);
            }
        } else {
            if (StringUtils.isNotEmpty(api)
                    && (context.getProperty(EmailOTPAuthenticatorConstants.ACCESS_TOKEN_REQUIRED_APIS)) != null) {
                isRequired = String.valueOf(context.getProperty
                        (EmailOTPAuthenticatorConstants.ACCESS_TOKEN_REQUIRED_APIS)).contains(api);
            }
        }
        return isRequired;
    }

    private boolean isAPIKeyHeaderRequired(AuthenticationContext context, Map<String, String> emailOTPParameters,
                                           Map<String, String> authenticatorProperties)
            throws AuthenticationFailedException {
        boolean isRequired = false;
        Object propertiesFromLocal = null;
        String api = getAPI(authenticatorProperties);
        String tenantDomain = context.getTenantDomain();
        if (!tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, getName(), tenantDomain);
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            if (StringUtils.isNotEmpty(api)
                    && emailOTPParameters.containsKey(EmailOTPAuthenticatorConstants.API_KEY_HEADER_REQUIRED_APIS)) {
                isRequired = emailOTPParameters.get(EmailOTPAuthenticatorConstants.API_KEY_HEADER_REQUIRED_APIS)
                        .contains(api);
            }
        } else {
            if (StringUtils.isNotEmpty(api)
                    && (context.getProperty(EmailOTPAuthenticatorConstants.API_KEY_HEADER_REQUIRED_APIS)) != null) {
                isRequired = String.valueOf(context.getProperty
                        (EmailOTPAuthenticatorConstants.API_KEY_HEADER_REQUIRED_APIS)).contains(api);
            }
        }
        return isRequired;
    }

    private String getAPI(Map<String, String> authenticatorProperties) {
        return authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAIL_API).trim();
    }

    private String sendMailUsingAPIs(AuthenticationContext context, Map<String, String> authenticatorProperties,
                                     Map<String, String> emailOTPParameters, String urlParams,
                                     String payload, String formData) throws AuthenticationFailedException {
        String response = null;
        String api = getAPI(authenticatorProperties);
        String apiKey = EmailOTPUtils.getApiKey(context, emailOTPParameters, getName(), api);
        String endpoint = EmailOTPUtils.getMailingEndpoint(context, emailOTPParameters, getName(), api);
        if ((isAccessTokenRequired(context, emailOTPParameters, authenticatorProperties)
                && StringUtils.isEmpty(authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN)))
                || (isAPIKeyHeaderRequired(context, emailOTPParameters, authenticatorProperties)
                && StringUtils.isEmpty(apiKey))) {
            log.error("Required param '" + (isAccessTokenRequired(context, emailOTPParameters, authenticatorProperties)
                    ? EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN
                    : EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY) + "' cannot be null");
            return null;
        } else if (isAccessTokenRequired(context, emailOTPParameters, authenticatorProperties)
                || isAPIKeyHeaderRequired(context, emailOTPParameters, authenticatorProperties)) {
            String tokenType = EmailOTPUtils.getAuthTokenType(context, emailOTPParameters, getName(), api);
            if (StringUtils.isNotEmpty(endpoint) && StringUtils.isNotEmpty(tokenType)) {
                if (endpoint != null) {
                    response = sendRESTCall(endpoint.replace(EmailOTPAuthenticatorConstants.ADMIN_EMAIL
                                    , authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL))
                            , StringUtils.isNotEmpty(urlParams) ? urlParams : ""
                            , tokenType + " " + (isAccessTokenRequired(context, emailOTPParameters, authenticatorProperties)
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

    private String sendTokenRequest(AuthenticationContext context, Map<String, String> authenticatorProperties,
                                    Map<String, String> emailOTPParameters) throws AuthenticationFailedException {
        String response;
        String api = getAPI(authenticatorProperties);
        String refreshToken = EmailOTPUtils.getRefreshToken(context, emailOTPParameters, getName(), api);
        String clientId = EmailOTPUtils.getClientId(context, emailOTPParameters, getName(), api);
        String clientSecret = EmailOTPUtils.getClientSecret(context, emailOTPParameters, getName(), api);
        if (StringUtils.isNotEmpty(clientId) && StringUtils.isNotEmpty(clientSecret)
                && StringUtils.isNotEmpty(refreshToken)) {
            String formParams = EmailOTPAuthenticatorConstants.EMAILOTP_CLIENT_SECRET + "=" + clientSecret
                    + "&" + EmailOTPAuthenticatorConstants.EMAILOTP_GRANT_TYPE + "="
                    + EmailOTPAuthenticatorConstants.EMAILOTP_GRANT_TYPE_REFRESH_TOKEN + "&"
                    + EmailOTPAuthenticatorConstants.EMAILOTP_GRANT_TYPE_REFRESH_TOKEN + "=" + refreshToken
                    + "&" + EmailOTPAuthenticatorConstants.EMAILOTP_CLIENT_ID + "=" + clientId;
            response = sendRESTCall(getTokenEndpoint(context, authenticatorProperties, emailOTPParameters), "", "", formParams, ""
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
    protected String getTokenEndpoint(AuthenticationContext context, Map<String, String> authenticatorProperties,
                                      Map<String, String> emailOTPParameters) throws AuthenticationFailedException {
        String api = getAPI(authenticatorProperties);
        String tokenEndpoint = EmailOTPUtils.getAccessTokenEndpoint(context, emailOTPParameters, getName(), api);
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

    private boolean isSMTP(Map<String, String> authenticatorProperties, Map<String, String> emailOTPParameters,
                           AuthenticationContext context) throws AuthenticationFailedException {
        String api = getAPI(authenticatorProperties);
        String mailingEndpoint = EmailOTPUtils.getMailingEndpoint(context, emailOTPParameters, getName(), api);
        String apiKey = EmailOTPUtils.getApiKey(context, emailOTPParameters, getName(), api);
        String refreshToken = EmailOTPUtils.getRefreshToken(context, emailOTPParameters, getName(), api);
        String clientId = EmailOTPUtils.getClientId(context, emailOTPParameters, getName(), api);
        String clientSecret = EmailOTPUtils.getClientSecret(context, emailOTPParameters, getName(), api);
        String email = authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL);
        return StringUtils.isEmpty(email) || StringUtils.isEmpty(api) || StringUtils.isEmpty(mailingEndpoint)
                || (!isAccessTokenRequired(context, emailOTPParameters, authenticatorProperties) && StringUtils.isEmpty(apiKey))
                || (isAccessTokenRequired(context, emailOTPParameters, authenticatorProperties)
                && (StringUtils.isEmpty(refreshToken) || StringUtils.isEmpty(clientId)
                || StringUtils.isEmpty(clientSecret)));
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter("sessionDataKey");
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