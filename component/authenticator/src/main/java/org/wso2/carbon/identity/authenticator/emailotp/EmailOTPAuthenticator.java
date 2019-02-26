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
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
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
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.emailotp.config.EmailOTPUtils;
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
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of EmailOTP
 */
public class EmailOTPAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(EmailOTPAuthenticator.class);

    /**
     * Check whether the authentication or logout request can be handled by the authenticator
     */
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside EmailOTPAuthenticator canHandle method");
        }
        return ((StringUtils.isNotEmpty(request.getParameter(EmailOTPAuthenticatorConstants.RESEND))
                && StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.CODE)))
                || StringUtils.isNotEmpty(request.getParameter(EmailOTPAuthenticatorConstants.CODE))
                || StringUtils.isNotEmpty(request.getParameter(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS)));
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {
        // if the logout request comes, then no need to go through and complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (StringUtils.isNotEmpty(request.getParameter(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS))) {
            // if the request comes with EMAIL ADDRESS, it will go through this flow.
            initiateAuthenticationRequest(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
        } else if (StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.CODE))) {
            // if the request comes with code, it will go through this flow.
            initiateAuthenticationRequest(request, response, context);
            if (context.getProperty(EmailOTPAuthenticatorConstants.AUTHENTICATION)
                    .equals(EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME)) {
                // if the request comes with authentication is EmailOTP, it will go through this flow.
                // set the current authenticator name
                context.setCurrentAuthenticator(getName());
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
            boolean isEmailOTPMandatory, sendOtpToFederatedEmail;
            Object propertiesFromLocal = null;
            String email;
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
            FederatedAuthenticatorUtil.setUsernameFromFirstStep(context);
            String username = String.valueOf(context.getProperty(EmailOTPAuthenticatorConstants.USER_NAME));
            authenticatedUser = (AuthenticatedUser) context.getProperty
                    (EmailOTPAuthenticatorConstants.AUTHENTICATED_USER);
            // find the authenticated user.
            if (authenticatedUser == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Cannot find the authenticated user, the username : " + username + " may be null");
                }
                throw new AuthenticationFailedException
                        ("Authentication failed!. Cannot find the authenticated user, the username : "
                                + username + " may be null");
            }
            boolean isUserExistence = FederatedAuthenticatorUtil.isUserExistInUserStore(username);
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(
                    context.getQueryParams(), context.getCallerSessionKey(),
                    context.getContextIdentifier());
            if (isEmailOTPMandatory) {
                if (log.isDebugEnabled()) {
                    log.debug("Process the EmailOTP mandatory flow ");
                }
                processEmailOTPMandatory(context, request, response, isUserExistence, username, queryParams,
                        emailOTPParameters, sendOtpToFederatedEmail);
            } else if (isUserExistence && !isEmailOTPDisableForUser(username, context,
                    emailOTPParameters)) {
                if (log.isDebugEnabled()) {
                    log.debug("Process the EmailOTP optional flow, but user enable emailOTP as second step ");
                }
                email = getEmailValueForUsername(username, context);
                if (StringUtils.isEmpty(email)) {
                    if (request.getParameter(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS) == null) {
                        redirectToEmailAddressReqPage(response, context, emailOTPParameters, queryParams, username);
                    } else {
                        updateEmailAddressForUsername(context, request, username);
                        email = getEmailValueForUsername(username, context);
                    }
                }
                if (StringUtils.isNotEmpty(email)) {
                    processEmailOTPFlow(request, response, email, username, queryParams, context);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Process with the first step (basic) authenticator only");
                }
                processFirstStepOnly(authenticatedUser, context);
            }
        } catch (EmailOTPException e) {
            throw new AuthenticationFailedException("Failed to get the email claim when proceed the EmailOTP flow ", e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to get the user from user store ", e);
        }
    }

    /**
     * Process the response of the EmailOTP end-point
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {
        if (StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.CODE))) {
            if (log.isDebugEnabled()) {
                log.debug("One time password cannot be null");
            }
            throw new InvalidCredentialsException("Code cannot be null");
        }
        if (Boolean.parseBoolean(request.getParameter(EmailOTPAuthenticatorConstants.RESEND))) {
            if (log.isDebugEnabled()) {
                log.debug("Retrying to resend the OTP");
            }
            throw new InvalidCredentialsException("Retrying to resend the OTP");
        }
        String userToken = request.getParameter(EmailOTPAuthenticatorConstants.CODE);
        String contextToken = (String) context.getProperty(EmailOTPAuthenticatorConstants.OTP_TOKEN);
        long genTime = (long)context.getProperty(EmailOTPAuthenticatorConstants.OTP_GENERATED_TIME);
        if (userToken.equals(contextToken)  && System.currentTimeMillis()<=genTime+new Long(new EmailOTPAuthenticator().getExpireTime(context))) {
            context.setProperty(EmailOTPAuthenticatorConstants.OTP_TOKEN, "");
            context.setProperty(EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN, "");
            String emailFromProfile = context.getProperty(EmailOTPAuthenticatorConstants.RECEIVER_EMAIL).toString();
            context.setSubject(AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(emailFromProfile));
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Given otp code is mismatch or otp expired ");
            }
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
            String urlParams = prepareURLParams(context, authenticatorProperties, emailOTPParameters);
            String sendCodeResponse = sendMailUsingAPIs(context, authenticatorProperties, emailOTPParameters, urlParams,
                    payload, formData);
            String api = getAPI(authenticatorProperties);
            String failureString = getFailureString(context, emailOTPParameters, api);
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
                if (log.isDebugEnabled()) {
                    log.debug("Unable to get the access token");
                }
                throw new AuthenticationFailedException("Error while getting the access token");
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
     * @param context           the authentication context
     * @param authenticatorName the authenticator name
     * @return the key of federatedEmailAttribute
     * @throws AuthenticationFailedException
     */
    private String getFederatedEmailAttributeKey(AuthenticationContext context, String authenticatorName)
            throws AuthenticationFailedException {
        String federatedEmailAttributeKey = null;
        Map<String, String> parametersMap;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if (propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) {
            parametersMap = FederatedAuthenticatorUtil.getAuthenticatorConfig(authenticatorName);
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
     *
     * @param context                 the AuthenticationContext
     * @param request                 the HttpServletRequest
     * @param response                the HttpServletResponse
     * @param isUserExistence         check userExistence
     * @param username                the username
     * @param queryParams             the queryParams
     * @param emailOTPParameters      the emailotp parameters
     * @param sendOtpToFederatedEmailAddress check otp directly send to federated email attribute is enable or not
     * @throws EmailOTPException
     * @throws AuthenticationFailedException
     */
    private void processEmailOTPMandatory(AuthenticationContext context, HttpServletRequest request,
                                          HttpServletResponse response, boolean isUserExistence, String username,
                                          String queryParams, Map<String, String> emailOTPParameters,
                                          boolean sendOtpToFederatedEmailAddress)
            throws EmailOTPException, AuthenticationFailedException {
        String email = null;
        if (isUserExistence) {
            if (isEmailOTPDisableForUser(username, context, emailOTPParameters)) {
                // Email OTP authentication is mandatory and user doesn't have Email value in user's profile.
                // Cannot proceed further without EmailOTP authentication.
                String retryParam = EmailOTPAuthenticatorConstants.ERROR_EMAILOTP_DISABLE;
                redirectToErrorPage(response, context, emailOTPParameters, queryParams, retryParam);
            } else {
                // Email OTP authentication is mandatory and user have Email value in user's profile.
                email = getEmailValueForUsername(username, context);
                if (StringUtils.isEmpty(email)) {
                    if (request.getParameter(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS) == null) {
                        redirectToEmailAddressReqPage(response, context, emailOTPParameters, queryParams, username);
                    } else {
                        updateEmailAddressForUsername(context, request, username);
                        email = getEmailValueForUsername(username, context);
                    }
                }
            }
            if (StringUtils.isNotEmpty(email)) {
                processEmailOTPFlow(request, response, email, username, queryParams, context);
            }
        } else {
            proceedOTPWithFederatedEmailAddress(context, request, response, username, queryParams,
                    sendOtpToFederatedEmailAddress, emailOTPParameters);
        }
    }

    /**
     * Update email address for specific username when user forgets to update the email address in user's profile.
     *
     * @param context  the AuthenticationContext
     * @param request  the HttpServletRequest
     * @param username the Username
     * @throws AuthenticationFailedException
     */
    private void updateEmailAddressForUsername(AuthenticationContext context, HttpServletRequest request,
                                               String username)
            throws AuthenticationFailedException {
        String tenantDomain = context.getTenantDomain();
        if (username != null && !context.isRetrying()) {
            Map<String, String> attributes = new HashMap<>();
            attributes.put(EmailOTPAuthenticatorConstants.EMAIL_CLAIM,
                    request.getParameter(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS));
            updateUserAttribute(MultitenantUtils.getTenantAwareUsername(username), attributes, tenantDomain);
        }
    }

    /**
     * Update the email address (user attribute) in user's profile.
     *
     * @param username  the Username
     * @param attribute the Attribute
     */
    private void updateUserAttribute(String username, Map<String, String> attribute, String tenantDomain)
            throws AuthenticationFailedException {
        try {
            // updating user attributes is independent from tenant association.not tenant association check needed here.
            // user is always in the super tenant.
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
            if (userRealm == null) {
                throw new AuthenticationFailedException("The specified tenant domain " + tenantDomain
                        + " does not exist.");
            }
            // check whether user already exists in the system.
            verifyUserExists(username, tenantDomain);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            userStoreManager.setUserClaimValues(username, attribute, null);
        } catch (UserStoreException | AuthenticationFailedException e) {
            throw new AuthenticationFailedException("Exception occurred while connecting to User Store:" +
                    " Authentication is failed. ", e);
        }
    }

    /**
     * Verify whether user Exist in the user store or not.
     *
     * @param username     the Username
     * @param tenantDomain the tenant domain
     * @throws AuthenticationFailedException
     */
    private void verifyUserExists(String username, String tenantDomain) throws AuthenticationFailedException {
        UserRealm userRealm;
        boolean isUserExist = false;
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            if (userRealm == null) {
                throw new AuthenticationFailedException("Super tenant realm not loaded.");
            }
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager.isExistingUser(username)) {
                isUserExist = true;
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error while validating the user :" + username, e);
        }
        if (!isUserExist) {
            if (log.isDebugEnabled()) {
                log.debug("User does not exist in the User Store");
            }
            throw new AuthenticationFailedException("User does not exist in the User Store.");
        }
    }

    /**
     * Redirect the user to email address request page where user forgets to register email address
     * in EmailOTP mandatory case.
     *
     * @param response    the HttpServletResponse
     * @param context     the AuthenticationContext
     * @param queryParams the queryParams
     * @throws AuthenticationFailedException
     */
    private void redirectToEmailAddressReqPage(HttpServletResponse response, AuthenticationContext context,
                                               Map<String, String> emailOTPParameters, String queryParams,
                                               String username)
            throws AuthenticationFailedException {
        boolean isEmailAddressUpdateEnable = isEmailAddressUpdateEnable(context, emailOTPParameters);
        if (isEmailAddressUpdateEnable) {
            String emailAddressReqPage = getEmailAddressRequestPage(context, emailOTPParameters);
            try {
                String url = getRedirectURL(emailAddressReqPage, queryParams);
                response.sendRedirect(url);
            } catch (IOException e) {
                throw new AuthenticationFailedException("Authentication failed!. An IOException was caught while " +
                        "redirecting to email address request page. ", e);
            }
        } else {
            throw new AuthenticationFailedException("Authentication failed!. Update email address for the user : "
                    + username);
        }
    }

    /**
     * To get the redirection URL.
     *
     * @param baseURI     the base path
     * @param queryParams the queryParams
     * @return url
     */
    private String getRedirectURL(String baseURI, String queryParams) {
        String url;
        if (StringUtils.isNotEmpty(queryParams)) {
            url = baseURI + "?" + queryParams + "&" + EmailOTPAuthenticatorConstants.AUTHENTICATORS + getName();
        } else {
            url = baseURI + "?" + EmailOTPAuthenticatorConstants.AUTHENTICATORS + getName();
        }
        return url;
    }

    /**
     * In EmailOTP mandatory case, If user not found in the directory then send otp directly to federated email
     *
     * @param context                 the AuthenticationContext
     * @param request                 the HttpServletRequest
     * @param response                the HttpServletResponse
     * @param username                the username
     * @param queryParams             the queryParams
     * @param sendOtpToFederatedEmail check whether directly send otp federated email attribute is enable or not
     * @throws AuthenticationFailedException
     */
    private void proceedOTPWithFederatedEmailAddress(AuthenticationContext context, HttpServletRequest request,
                                            HttpServletResponse response, String username, String queryParams,
                                            boolean sendOtpToFederatedEmail, Map<String, String> emailOTPParameters)
            throws AuthenticationFailedException {
        try {
            String federatedEmailAttributeKey;
            String email = null;
            StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
            String previousStepAuthenticator = stepConfig.getAuthenticatedAutenticator().getName();
            StepConfig currentStep = context.getSequenceConfig().getStepMap().get(context.getCurrentStep());
            String currentStepAuthenticator = currentStep.getAuthenticatorList().iterator().next().getName();
            if (sendOtpToFederatedEmail) {
                federatedEmailAttributeKey = getFederatedEmailAttributeKey(context, previousStepAuthenticator);
                if (StringUtils.isEmpty(federatedEmailAttributeKey)) {
                    federatedEmailAttributeKey = getFederatedEmailAttributeKey(context, currentStepAuthenticator);
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
                        processEmailOTPFlow(request, response, email, username, queryParams, context);
                        break;
                    }
                }
                if (StringUtils.isEmpty(email)) {
                    if (log.isDebugEnabled()) {
                        log.debug("There is no email claim to send otp ");
                    }
                    throw new AuthenticationFailedException("There is no email claim to send otp");
                }
            } else {
                String retryParam = EmailOTPAuthenticatorConstants.SEND_OTP_DIRECTLY_DISABLE;
                redirectToErrorPage(response, context, emailOTPParameters, queryParams, retryParam);
            }
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException(" Failed to process EmailOTP flow ", e);
        }
    }

    /**
     * In EmailOTP optional case, If uer not found or email claim doesn't enable then process the first step only
     *
     * @param authenticatedUser the authenticatedUser
     * @param context           the AuthenticationContext
     */
    private void processFirstStepOnly(AuthenticatedUser authenticatedUser, AuthenticationContext context) {
        //the authentication flow happens with basic authentication (First step only).
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        if (stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof
                LocalApplicationAuthenticator) {
            FederatedAuthenticatorUtil.updateLocalAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(EmailOTPAuthenticatorConstants.AUTHENTICATION, EmailOTPAuthenticatorConstants.BASIC);
        } else {
            FederatedAuthenticatorUtil.updateAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(EmailOTPAuthenticatorConstants.AUTHENTICATION, EmailOTPAuthenticatorConstants.FEDERETOR);
        }
    }

    /**
     * To redirect flow to error page with specific condition
     *
     * @param response the httpServletResponse
     * @param context the AuthenticationContext
     * @param emailOTPParameters the emailotp parameters
     * @param queryParams the query params
     * @param retryParam the retry param
     * @throws AuthenticationFailedException
     */
    private void redirectToErrorPage(HttpServletResponse response, AuthenticationContext context,
                                     Map<String, String> emailOTPParameters, String queryParams, String retryParam)
            throws AuthenticationFailedException {
        try {
            // Full url of the error page
            String errorPage = getEmailOTPErrorPage(context, emailOTPParameters);
            if (log.isDebugEnabled()) {
                log.debug("The EmailOTP error page url is " + errorPage);
            }
            if (StringUtils.isEmpty(errorPage)) {
                String authenticationEndpointURL = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
                errorPage = authenticationEndpointURL.replace(EmailOTPAuthenticatorConstants.LOGIN_PAGE,
                        EmailOTPAuthenticatorConstants.ERROR_PAGE);
                if (log.isDebugEnabled()) {
                    log.debug("The default authentication endpoint URL " + authenticationEndpointURL +
                            "is replaced by default email otp error page " + errorPage);
                }
                if (!errorPage.contains(EmailOTPAuthenticatorConstants.ERROR_PAGE)) {
                    throw new AuthenticationFailedException("The default authentication page is not replaced by default"
                            + " email otp error page");
                }
            }
            String url = getRedirectURL(errorPage, queryParams);
            response.sendRedirect(url + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Authentication Failed : An IO Exception caught," +
                    " While redirecting to error page ", e);
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
     * @param context     the authentication context
     * @throws AuthenticationFailedException
     */
    private void processEmailOTPFlow(HttpServletRequest request, HttpServletResponse response, String email,
                                     String username, String queryParams,
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
                context.setProperty(EmailOTPAuthenticatorConstants.OTP_GENERATED_TIME,System.currentTimeMillis());
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
                redirectToEmailOTPLoginPage(response,context,emailOTPParameters,queryParams,email);
            }
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException("Authentication Failed: Authenticator Properties may be null ", e);
        }
    }

    /**
     * To redirect the flow to email otp login page to enter an OTP
     *
     * @throws AuthenticationFailedException
     */
    private void redirectToEmailOTPLoginPage(HttpServletResponse response, AuthenticationContext context,
                                             Map<String, String> emailOTPParameters, String queryParams,
                                             String email) throws AuthenticationFailedException {
        try {
            // Full url of the login page
            String emailOTPLoginPage = getEmailOTPLoginPage(context, emailOTPParameters);
            if (log.isDebugEnabled()) {
                log.debug("The EmailOTP login page url is " + emailOTPLoginPage);
            }
            if (StringUtils.isEmpty(emailOTPLoginPage)) {
                String authenticationEndpointURL = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
                emailOTPLoginPage = authenticationEndpointURL.replace(EmailOTPAuthenticatorConstants.LOGIN_PAGE,
                        EmailOTPAuthenticatorConstants.EMAILOTP_PAGE);
                if (log.isDebugEnabled()) {
                    log.debug("The default authentication endpoint URL " + authenticationEndpointURL +
                            "is replaced by default email otp login page " + emailOTPLoginPage);
                }
                if (!emailOTPLoginPage.contains(EmailOTPAuthenticatorConstants.EMAILOTP_PAGE)) {
                    throw new AuthenticationFailedException("The default authentication page is not replaced by default"
                            + " email otp page");
                }
            }
            String url = getRedirectURL(emailOTPLoginPage, queryParams);
            if (isShowEmailAddressInUIEnable(context, emailOTPParameters)) {
                url = url + EmailOTPAuthenticatorConstants.SCREEN_VALUE + email;
            }
            if (context.isRetrying()) {
                url = url + EmailOTPAuthenticatorConstants.RETRY_PARAMS;
            }
            response.sendRedirect(url);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Authentication Failed: An IOException was caught while " +
                    "redirecting to login page. ", e);
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
            URLConnection  urlConnection = emailOTPEP.openConnection();
            if (urlConnection instanceof HttpURLConnection) {
                connection = (HttpURLConnection) urlConnection;
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
                    OutputStreamWriter writer = new OutputStreamWriter(connection.getOutputStream(),
                            EmailOTPAuthenticatorConstants.CHARSET);
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
            }
        } catch (ProtocolException e) {
            if (log.isDebugEnabled()) {
                log.debug(EmailOTPAuthenticatorConstants.FAILED + " May be the query parameter too long ", e);
            }
            return EmailOTPAuthenticatorConstants.FAILED;
        } catch (MalformedURLException e) {
            if (log.isDebugEnabled()) {
                log.debug(EmailOTPAuthenticatorConstants.FAILED + " The constructed URL may be wrong ", e);
            }
            return EmailOTPAuthenticatorConstants.FAILED;
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug(EmailOTPAuthenticatorConstants.FAILED + " An IOException occurred while perform a rest call "
                        + "with API endpoint ", e);
            }
            return EmailOTPAuthenticatorConstants.FAILED;
        }
        finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
        return responseString.toString();
    }

    /**
     * Prepare the payload to send otp via API's
     *
     * @param context                 the AuthenticationContext
     * @param authenticatorProperties the authenticatorProperties
     * @param emailOTPParameters      the emailOTPParameters
     * @param email                   the email address to send otp
     * @param otp                     the one time password
     * @return the payload
     * @throws AuthenticationFailedException
     */
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
            payload = getPreparePayload(context, emailOTPParameters, api);
            if (StringUtils.isNotEmpty(payload)) {
                String fromMail = authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL);
                String apiKey = getApiKey(context, emailOTPParameters, api);
                payload = payload.replace(EmailOTPAuthenticatorConstants.MAIL_FROM_EMAIL, fromMail);
                payload = payload.replace(EmailOTPAuthenticatorConstants.MAIL_TO_EMAIL, email);
                payload = payload.replace(EmailOTPAuthenticatorConstants.MAIL_BODY, otp);
                payload = payload.replace(EmailOTPAuthenticatorConstants.MAIL_API_KEY, apiKey);
            }
        }
        return payload;
    }

    /**
     * Prepare the required URL params to send otp via API's
     *
     * @param context                 the AuthenticationContext
     * @param authenticatorProperties the authenticatorProperties
     * @param emailOTPParameters      the emailOTPParameters
     * @return the urlParams
     * @throws AuthenticationFailedException
     */
    private String prepareURLParams(AuthenticationContext context, Map<String, String> authenticatorProperties,
                                    Map<String, String> emailOTPParameters)
            throws AuthenticationFailedException {
        String api = getAPI(authenticatorProperties);
        String urlParams = getPrepareURLParams(context, emailOTPParameters, api);
        return StringUtils.isNotEmpty(urlParams) ? urlParams : null;
    }

    /**
     * Prepare the required form data to send otp via API's
     *
     * @param context                 the AuthenticationContext
     * @param authenticatorProperties the authenticatorProperties
     * @param emailOTPParameters      the emailOTPParameters
     * @param email                   the email address to send otp
     * @param otp                     the one time password
     * @return the formData
     * @throws AuthenticationFailedException
     */
    private String prepareFormData(AuthenticationContext context, Map<String, String> authenticatorProperties,
                                   Map<String, String> emailOTPParameters, String email, String otp)
            throws AuthenticationFailedException {
        String api = getAPI(authenticatorProperties);
        String formData = getPrepareFormData(context, emailOTPParameters, api);
        if (StringUtils.isNotEmpty(formData)) {
            String fromMail = authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL);
            String apiKey = getApiKey(context, emailOTPParameters, api);
            formData = formData.replace(EmailOTPAuthenticatorConstants.MAIL_FROM_EMAIL, fromMail);
            formData = formData.replace(EmailOTPAuthenticatorConstants.MAIL_TO_EMAIL, email);
            formData = formData.replace(EmailOTPAuthenticatorConstants.MAIL_BODY, otp);
            formData = formData.replace(EmailOTPAuthenticatorConstants.MAIL_API_KEY, apiKey);
        }
        return formData;
    }

    /**
     * Check Which api need access token
     *
     * @param context                 the AuthenticationContext
     * @param emailOTPParameters      the emailOTPParameters
     * @param authenticatorProperties the authenticatorProperties
     * @return true or false
     * @throws AuthenticationFailedException
     */
    private boolean isAccessTokenRequired(AuthenticationContext context, Map<String, String> emailOTPParameters,
                                          Map<String, String> authenticatorProperties)
            throws AuthenticationFailedException {
        boolean isRequired = false;
        String api = getAPI(authenticatorProperties);
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
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

    /**
     * Check which api need apiKey as a header
     *
     * @param context                 the AuthenticationContext
     * @param emailOTPParameters      the emailOTPParameters
     * @param authenticatorProperties the authenticatorProperties
     * @return true or false
     * @throws AuthenticationFailedException
     */
    private boolean isAPIKeyHeaderRequired(AuthenticationContext context, Map<String, String> emailOTPParameters,
                                           Map<String, String> authenticatorProperties)
            throws AuthenticationFailedException {
        boolean isRequired = false;
        String api = getAPI(authenticatorProperties);
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
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

    /**
     * Check whether EmailOTP is disable by user.
     *
     * @param username the Username
     * @param context  the AuthenticationContext
     * @return true or false
     */
    private boolean isEmailOTPDisableForUser(String username, AuthenticationContext context,
                                             Map<String, String> parametersMap)
            throws AuthenticationFailedException {
        UserRealm userRealm;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            username = MultitenantUtils.getTenantAwareUsername(String.valueOf(username));
            if (userRealm != null) {
                if (isAdminMakeUserToEnableOrDisableEmailOTP(context, parametersMap)) {
                    Map<String, String> claimValues = userRealm.getUserStoreManager().getUserClaimValues(username,
                            new String[]{EmailOTPAuthenticatorConstants.USER_EMAILOTP_DISABLED_CLAIM_URI}, null);
                    String isEmailOTPEnabledByUser = claimValues.
                            get(EmailOTPAuthenticatorConstants.USER_EMAILOTP_DISABLED_CLAIM_URI);
                    return Boolean.parseBoolean(isEmailOTPEnabledByUser);
                }
            } else {
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant domain : "
                        + tenantDomain);
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed while trying to access userRealm of the user : "
                    + username, e);
        }
        return false;
    }


    /**
     * Check whether Admin gives the priority to user to make the two factor authentication as optional.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    private boolean isAdminMakeUserToEnableOrDisableEmailOTP(AuthenticationContext context,
                                                                   Map<String, String> parametersMap) {
        boolean isAdminMakeUserToEnableEmailOTP = false;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(EmailOTPAuthenticatorConstants.IS_EMAILOTP_ENABLE_BY_USER)) {
            isAdminMakeUserToEnableEmailOTP = Boolean.parseBoolean(parametersMap.get
                    (EmailOTPAuthenticatorConstants.IS_EMAILOTP_ENABLE_BY_USER));
        } else if ((context.getProperty(EmailOTPAuthenticatorConstants.IS_EMAILOTP_ENABLE_BY_USER)) != null) {
            isAdminMakeUserToEnableEmailOTP = Boolean.parseBoolean(String.valueOf(context.getProperty
                    (EmailOTPAuthenticatorConstants.IS_EMAILOTP_ENABLE_BY_USER)));
        }
        return isAdminMakeUserToEnableEmailOTP;
    }

    /**
     * Get email value for username
     *
     * @param username the user name
     * @param context  the authentication context
     * @return email
     * @throws EmailOTPException
     */
    private String getEmailValueForUsername(String username, AuthenticationContext context)
            throws EmailOTPException {
        UserRealm userRealm;
        String tenantAwareUsername;
        String email;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            if (userRealm != null) {
                email = userRealm.getUserStoreManager()
                        .getUserClaimValue(tenantAwareUsername, EmailOTPAuthenticatorConstants.EMAIL_CLAIM, null);
                context.setProperty(EmailOTPAuthenticatorConstants.RECEIVER_EMAIL, email);
            } else {
                throw new EmailOTPException("Cannot find the user realm for the given tenant domain : " + tenantDomain);
            }
        } catch (UserStoreException e) {
            throw new EmailOTPException("Cannot find the email claim for username : " + username, e);
        }
        return email;
    }

    /**
     * Get clientId for Gmail APIs
     */
    private String getClientId(AuthenticationContext context, Map<String, String> parametersMap, String api) {
        String clientId = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(api + OIDCAuthenticatorConstants.CLIENT_ID)) {
            clientId = parametersMap.get(api + OIDCAuthenticatorConstants.CLIENT_ID);
        } else if ((context.getProperty(api + OIDCAuthenticatorConstants.CLIENT_ID)) != null) {
            clientId = String.valueOf(context.getProperty(api + OIDCAuthenticatorConstants.CLIENT_ID));
        }
        return clientId;
    }

    /**
     * Get clientSecret for Gmail APIs
     */
    private String getClientSecret(AuthenticationContext context, Map<String, String> parametersMap, String api) {
        String clientSecret = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(api + OIDCAuthenticatorConstants.CLIENT_SECRET)) {
            clientSecret = parametersMap.get(api + OIDCAuthenticatorConstants.CLIENT_SECRET);
        } else if ((context.getProperty(api + OIDCAuthenticatorConstants.CLIENT_SECRET)) != null) {
            clientSecret = String.valueOf(context.getProperty(api + OIDCAuthenticatorConstants.CLIENT_SECRET));
        }
        return clientSecret;
    }

    /**
     * Get RefreshToken for Gmail APIs
     */
    private String getRefreshToken(AuthenticationContext context, Map<String, String> parametersMap, String api) {
        String refreshToken = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.REFRESH_TOKEN)) {
            refreshToken = parametersMap.get(api + EmailOTPAuthenticatorConstants.REFRESH_TOKEN);
        } else if ((context.getProperty(api + EmailOTPAuthenticatorConstants.REFRESH_TOKEN)) != null) {
            refreshToken = String.valueOf(context.getProperty(api + EmailOTPAuthenticatorConstants.REFRESH_TOKEN));
        }
        return refreshToken;
    }

    /**
     * Get ApiKey for Gmail APIs
     */
    private String getApiKey(AuthenticationContext context, Map<String, String> parametersMap, String api) {
        String apiKey = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY)) {
            apiKey = parametersMap.get(api + EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY);
        } else if ((context.getProperty(api + EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY)) != null) {
            apiKey = String.valueOf(context.getProperty(api + EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY));
        }
        return apiKey;
    }

    /**
     * Get MailingEndpoint for Gmail APIs
     */
    private String getMailingEndpoint(AuthenticationContext context, Map<String, String> parametersMap,
                                            String api) {
        String mailingEndpoint = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.MAILING_ENDPOINT)) {
            mailingEndpoint = parametersMap.get(api + EmailOTPAuthenticatorConstants.MAILING_ENDPOINT);
        } else if ((context.getProperty(api + EmailOTPAuthenticatorConstants.MAILING_ENDPOINT)) != null) {
            mailingEndpoint = String.valueOf(context.getProperty
                    (api + EmailOTPAuthenticatorConstants.MAILING_ENDPOINT));
        }
        return mailingEndpoint;
    }

    /**
     * Get required payload for Gmail APIs
     */
    private String getPreparePayload(AuthenticationContext context, Map<String, String> parametersMap,
                                           String api) {
        String payload = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.PAYLOAD)) {
            payload = parametersMap.get(api + EmailOTPAuthenticatorConstants.PAYLOAD);
        } else if ((context.getProperty(api + EmailOTPAuthenticatorConstants.PAYLOAD)) != null) {
            payload = String.valueOf(context.getProperty(api + EmailOTPAuthenticatorConstants.PAYLOAD));
        }
        return payload;
    }

    /**
     * Get required FormData for Gmail APIs
     */
    private String getPrepareFormData(AuthenticationContext context, Map<String, String> parametersMap,
                                            String api) {
        String prepareFormData = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.FORM_DATA)) {
            prepareFormData = parametersMap.get(api + EmailOTPAuthenticatorConstants.FORM_DATA);
        } else if ((context.getProperty(api + EmailOTPAuthenticatorConstants.FORM_DATA)) != null) {
            prepareFormData = String.valueOf(context.getProperty(api + EmailOTPAuthenticatorConstants.FORM_DATA));
        }
        return prepareFormData;
    }

    /**
     * Get required URL params for Gmail APIs
     */
    private String getPrepareURLParams(AuthenticationContext context, Map<String, String> parametersMap,
                                             String api) {
        String prepareUrlParams = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.URL_PARAMS)) {
            prepareUrlParams = parametersMap.get(api + EmailOTPAuthenticatorConstants.URL_PARAMS);
        } else if ((context.getProperty(api + EmailOTPAuthenticatorConstants.URL_PARAMS)) != null) {
            prepareUrlParams = String.valueOf(context.getProperty(api + EmailOTPAuthenticatorConstants.URL_PARAMS));
        }
        return prepareUrlParams;
    }

    /**
     * Get failureString for Gmail APIs
     */
    private String getFailureString(AuthenticationContext context, Map<String, String> parametersMap, String api) {
        String failureString = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.FAILURE)) {
            failureString = parametersMap.get(api + EmailOTPAuthenticatorConstants.FAILURE);
        } else if ((context.getProperty(api + EmailOTPAuthenticatorConstants.FAILURE)) != null) {
            failureString = String.valueOf(context.getProperty(api + EmailOTPAuthenticatorConstants.FAILURE));
        }
        return failureString;
    }

    /**
     * Get AuthToken type for Gmail APIs
     */
    private String getAuthTokenType(AuthenticationContext context, Map<String, String> parametersMap, String api) {
        String authTokenType = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.HTTP_AUTH_TOKEN_TYPE)) {
            authTokenType = parametersMap.get(api + EmailOTPAuthenticatorConstants.HTTP_AUTH_TOKEN_TYPE);
        } else if ((context.getProperty(api + EmailOTPAuthenticatorConstants.HTTP_AUTH_TOKEN_TYPE)) != null) {
            authTokenType = String.valueOf(context.getProperty
                    (api + EmailOTPAuthenticatorConstants.HTTP_AUTH_TOKEN_TYPE));
        }
        return authTokenType;
    }

    /**
     * Get AccessToken endpoint for Gmail APIs
     */
    private String getAccessTokenEndpoint(AuthenticationContext context, Map<String, String> parametersMap,
                                                String api) {
        String tokenEndpoint = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.EMAILOTP_TOKEN_ENDPOINT)) {
            tokenEndpoint = parametersMap.get(api + EmailOTPAuthenticatorConstants.EMAILOTP_TOKEN_ENDPOINT);
        } else if ((context.getProperty(api + EmailOTPAuthenticatorConstants.EMAILOTP_TOKEN_ENDPOINT)) != null) {
            tokenEndpoint = String.valueOf(context.getProperty
                    (api + EmailOTPAuthenticatorConstants.EMAILOTP_TOKEN_ENDPOINT));
        }
        return tokenEndpoint;
    }

    /**
     * Get ErrorPage for Gmail APIs
     */
    private String getEmailOTPErrorPage(AuthenticationContext context, Map<String, String> parametersMap) {
        String errorPage = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ERROR_PAGE_URL)) {
            errorPage = parametersMap.get(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ERROR_PAGE_URL);
        } else if ((context.getProperty(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ERROR_PAGE_URL)) != null) {
            errorPage = String.valueOf(context.getProperty
                    (EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ERROR_PAGE_URL));
        }
        return errorPage;
    }

    /**
     * Get LoginPage for Gmail APIs
     */
    private String getEmailOTPLoginPage(AuthenticationContext context, Map<String, String> parametersMap) {
        String loginPage = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ENDPOINT_URL)) {
            loginPage = parametersMap.get(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ENDPOINT_URL);
        } else if ((context.getProperty(EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ENDPOINT_URL)) != null) {
            loginPage = String.valueOf(context.getProperty
                    (EmailOTPAuthenticatorConstants.EMAILOTP_AUTHENTICATION_ENDPOINT_URL));
        }
        return loginPage;
    }

    /**
     * Check whether admin enable to enter and update a email address in user profile when user forgets to register
     * the email claim value.
     *
     * @param context the AuthenticationContext
     * @return true or false
     */
    private boolean isEmailAddressUpdateEnable(AuthenticationContext context, Map<String, String> parametersMap) {
        boolean enableEmailAddressUpdate = false;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(EmailOTPAuthenticatorConstants.IS_ENABLE_EMAIL_VALUE_UPDATE)) {
            enableEmailAddressUpdate = Boolean.parseBoolean(parametersMap.get
                    (EmailOTPAuthenticatorConstants.IS_ENABLE_EMAIL_VALUE_UPDATE));
        } else if ((context.getProperty(EmailOTPAuthenticatorConstants.IS_ENABLE_EMAIL_VALUE_UPDATE)) != null) {
            enableEmailAddressUpdate = Boolean.parseBoolean(String.valueOf
                    (context.getProperty(EmailOTPAuthenticatorConstants.IS_ENABLE_EMAIL_VALUE_UPDATE)));
        }
        return enableEmailAddressUpdate;
    }

    /**
     * Get the email address request page url from the application-authentication.xml file.
     *
     * @param context the AuthenticationContext
     * @return email address request page
     */
    private String getEmailAddressRequestPage(AuthenticationContext context, Map<String, String> parametersMap) {
        String emailAddressReqPage = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS_REQ_PAGE)) {
            emailAddressReqPage = parametersMap.get(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS_REQ_PAGE);
        } else if ((context.getProperty(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS_REQ_PAGE)) != null) {
            emailAddressReqPage = String.valueOf(context.getProperty(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS_REQ_PAGE));
        }
        return emailAddressReqPage;
    }

    /**
     * Check whether can show the email address in UI where the otp is sent.
     *
     * @param context the AuthenticationContext
     * @return screenUserAttribute
     */
    private boolean isShowEmailAddressInUIEnable(AuthenticationContext context, Map<String, String> parametersMap) {
        boolean isShowEmailAddressInUI = false;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(EmailOTPAuthenticatorConstants.SHOW_EMAIL_ADDRESS_IN_UI)) {
            isShowEmailAddressInUI = Boolean.parseBoolean(parametersMap.get
                    (EmailOTPAuthenticatorConstants.SHOW_EMAIL_ADDRESS_IN_UI));
        } else if ((context.getProperty(EmailOTPAuthenticatorConstants.SHOW_EMAIL_ADDRESS_IN_UI)) != null) {
            isShowEmailAddressInUI = Boolean.parseBoolean(String.valueOf
                    (context.getProperty(EmailOTPAuthenticatorConstants.SHOW_EMAIL_ADDRESS_IN_UI)));
        }
        return isShowEmailAddressInUI;
    }

    private String getAPI(Map<String, String> authenticatorProperties) {
        return authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAIL_API).trim();
    }

    /**
     * Send mail (otp) using email API's
     *
     * @param context                 the AuthenticationContext
     * @param authenticatorProperties the authenticatorProperties
     * @param emailOTPParameters      the emailOTPParameters
     * @param urlParams               the required urlParams
     * @param payload                 the required payload
     * @param formData                the formData
     * @return the response
     * @throws AuthenticationFailedException
     */
    private String sendMailUsingAPIs(AuthenticationContext context, Map<String, String> authenticatorProperties,
                                     Map<String, String> emailOTPParameters, String urlParams,
                                     String payload, String formData) throws AuthenticationFailedException {
        String response = null;
        String api = getAPI(authenticatorProperties);
        String apiKey = getApiKey(context, emailOTPParameters, api);
        String endpoint = getMailingEndpoint(context, emailOTPParameters, api);
        if ((isAccessTokenRequired(context, emailOTPParameters, authenticatorProperties)
                && StringUtils.isEmpty(authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN)))
                || (isAPIKeyHeaderRequired(context, emailOTPParameters, authenticatorProperties)
                && StringUtils.isEmpty(apiKey))) {
            if (log.isDebugEnabled()) {
                log.debug("Required param '" + (isAccessTokenRequired(context, emailOTPParameters, authenticatorProperties)
                        ? EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN
                        : EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY) + "' cannot be null");
            }
            return null;
        } else if (isAccessTokenRequired(context, emailOTPParameters, authenticatorProperties)
                || isAPIKeyHeaderRequired(context, emailOTPParameters, authenticatorProperties)) {
            String tokenType = getAuthTokenType(context, emailOTPParameters, api);
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
                if (log.isDebugEnabled()) {
                    log.debug("The gmail api endpoint or access token type is empty");
                }
                return null;
            }
        } else {
            if (StringUtils.isNotEmpty(endpoint)) {
                response = sendRESTCall(endpoint, StringUtils.isNotEmpty(urlParams) ? urlParams : "", "", "", payload,
                        EmailOTPAuthenticatorConstants.HTTP_POST);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("The API endpoint is required to send OTP using API");
                }
                return null;
            }
        }
        return response;
    }

    /**
     * Proceed with token request with api endpoint.\
     *
     * @param context                 the AuthenticationContext
     * @param authenticatorProperties the authenticatorProperties
     * @param emailOTPParameters      the emailOTPParameters
     * @return the token response
     * @throws AuthenticationFailedException
     */
    private String sendTokenRequest(AuthenticationContext context, Map<String, String> authenticatorProperties,
                                    Map<String, String> emailOTPParameters) throws AuthenticationFailedException {
        String response;
        String api = getAPI(authenticatorProperties);
        String refreshToken = getRefreshToken(context, emailOTPParameters, api);
        String clientId = getClientId(context, emailOTPParameters, api);
        String clientSecret = getClientSecret(context, emailOTPParameters, api);
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
            if (log.isDebugEnabled()) {
                log.debug("Required params " + "ClientID : " + clientId + " Or ClientSecret : " + clientSecret
                        + " may be null: ");
            }
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
        String tokenEndpoint = getAccessTokenEndpoint(context, emailOTPParameters, api);
        return StringUtils.isNotEmpty(tokenEndpoint) ? tokenEndpoint : null;
    }

    /**
     * Send otp to email address via SMTP protocol.
     *
     * @param username the username
     * @param otp the one time password
     * @param email the email address to send otp
     * @throws AuthenticationFailedException
     */
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
                    if(log.isDebugEnabled()){
                        log.debug("Error occurred while loading email templates for user : " + username, e);
                    }
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
                        if(log.isDebugEnabled()){
                            log.debug("Error occurred while creating notification from email template : "
                                    + emailTemplate, e);
                        }
                        throw new AuthenticationFailedException("Error occurred while creating notification from " +
                                "email template : " + emailTemplate, e);
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
                throw new AuthenticationFailedException("MAILTO transport sender is not defined in axis2 " +
                        "configuration file");
            }
        } catch (AxisFault axisFault) {
            throw new AuthenticationFailedException("Error while getting the SMTP configuration");
        }
    }

    /**
     * Check whether SMTP protocol is used or email api is used to send otp to an email account
     *
     * @param authenticatorProperties the authenticatorProperties
     * @param emailOTPParameters      the emailOTPParameters
     * @param context                 the AuthenticationContext
     * @return true or false
     * @throws AuthenticationFailedException
     */
    private boolean isSMTP(Map<String, String> authenticatorProperties, Map<String, String> emailOTPParameters,
                           AuthenticationContext context) throws AuthenticationFailedException {
        String api = getAPI(authenticatorProperties);
        String mailingEndpoint = getMailingEndpoint(context, emailOTPParameters, api);
        String apiKey = getApiKey(context, emailOTPParameters, api);
        String refreshToken = getRefreshToken(context, emailOTPParameters, api);
        String clientId = getClientId(context, emailOTPParameters, api);
        String clientSecret = getClientSecret(context, emailOTPParameters, api);
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
    private String getExpireTime(AuthenticationContext context) throws AuthenticationFailedException {

        String expireTime = EmailOTPUtils.getExpirationTimeAttribute(context);
        if (StringUtils.isEmpty(expireTime)) {
            expireTime = EmailOTPAuthenticatorConstants.OTP_EXPIRE_TIME_DEFAULT;
            if (log.isDebugEnabled()) {
                log.debug("OTP Expiration Time not specified default value will be used");
            }
        }
        return expireTime;
    }
}