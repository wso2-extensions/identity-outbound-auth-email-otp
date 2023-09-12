/*
 *  Copyright (c) 2017, WSO2 LLC. (https://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
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
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.owasp.encoder.Encode;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationFlowHandler;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.authenticator.emailotp.config.EmailOTPUtils;
import org.wso2.carbon.identity.authenticator.emailotp.exception.EmailOTPException;
import org.wso2.carbon.identity.authenticator.emailotp.internal.EmailOTPServiceDataHolder;
import org.wso2.carbon.identity.captcha.connector.recaptcha.EmailOTPCaptchaConnector;
import org.wso2.carbon.identity.captcha.exception.CaptchaException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
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
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreClientException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorConstants.LOCAL_AUTHENTICATOR;
import static org.wso2.carbon.identity.authenticator.emailotp.EmailOTPUrlUtil.getEmailOTPErrorPageUrl;
import static org.wso2.carbon.identity.authenticator.emailotp.EmailOTPUrlUtil.getEmailOTPLoginPageUrl;
import static org.wso2.carbon.identity.authenticator.emailotp.EmailOTPUrlUtil.getRequestEmailPageUrl;

/**
 * Authenticator of EmailOTP.
 */
public class EmailOTPAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(EmailOTPAuthenticator.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (log.isDebugEnabled()) {
            log.debug("Inside EmailOTPAuthenticator canHandle method");
        }
        return ((StringUtils.isNotEmpty(request.getParameter(EmailOTPAuthenticatorConstants.RESEND))
                && StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.CODE)))
                || StringUtils.isNotEmpty(request.getParameter(EmailOTPAuthenticatorConstants.CODE))
                || StringUtils.isNotEmpty(request.getParameter(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS))
                || StringUtils.isNotEmpty(request.getParameter(EmailOTPAuthenticatorConstants.USER_NAME)));
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
        } else if (StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.CODE)) &&
                StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.RESEND))) {
            AuthenticatedUser authenticatedUser = getAuthenticatedUser(context);
            if (authenticatedUser == null) {
                if (StringUtils.isEmpty(request.getParameter(EmailOTPAuthenticatorConstants.USER_NAME))) {
                    redirectUserToIDF(response, context);
                    context.setProperty(EmailOTPAuthenticatorConstants.IS_IDF_INITIATED_FROM_AUTHENTICATOR, true);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                } else {
                    authenticatedUser = resolveUserFromRequest(request, context);
                    authenticatedUser = resolveUserFromUserStore(authenticatedUser);
                    setResolvedUserInContext(context, authenticatedUser);
                }
            } else if (isPreviousIdPAuthenticationFlowHandler(context)) {
                boolean isUserResolved = FrameworkUtils.getIsUserResolved(context);
                // Resolve the user from user store if the user is not resolved in IDF handler.
                if (!isUserResolved) {
                    authenticatedUser = resolveUserFromUserStore(authenticatedUser);
                }
                setResolvedUserInContext(context, authenticatedUser);
            }
            if (authenticatedUser != null) {
                initiateAuthenticationRequest(request, response, context);
                publishPostEmailOTPGeneratedEvent(request, context);
                if (context.getProperty(EmailOTPAuthenticatorConstants.AUTHENTICATION)
                        .equals(EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME)) {
                    /* If the request comes with authentication is EmailOTP, it will go through this flow.
                    set the current authenticator name. */
                    context.setCurrentAuthenticator(getName());
                    return AuthenticatorFlowStatus.INCOMPLETE;
                } else {
                    // if the request comes with authentication is basic, complete the flow.
                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                }
            } else {
                log.debug("The user does not exist in the user stores.");
                Map<String, String> emailOTPParameters = getAuthenticatorConfig().getParameterMap();
                String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                        context.getCallerSessionKey(), context.getContextIdentifier());
                redirectToEmailOTPLoginPage(response, request, context, emailOTPParameters, queryParams, null);
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
        } else if (Boolean.parseBoolean(request.getParameter(EmailOTPAuthenticatorConstants.RESEND))) {
            AuthenticatorFlowStatus authenticatorFlowStatus = super.process(request, response, context);
            publishPostEmailOTPGeneratedEvent(request, context);
            return authenticatorFlowStatus;
        } else {
            AuthenticatorFlowStatus authenticatorFlowStatus = super.process(request, response, context);
            publishPostEmailOTPValidatedEvent(request, context);
            return authenticatorFlowStatus;
        }
    }

    /**
     * Initiate the authentication request.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            boolean isEmailOTPMandatory;
            boolean sendOtpToFederatedEmail;
            String usecase;
            Object propertiesFromLocal = null;
            String email;
            AuthenticatedUser authenticatedUser = null;
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
                usecase = emailOTPParameters.get(EmailOTPAuthenticatorConstants.USE_CASE);
            } else {
                isEmailOTPMandatory = Boolean.parseBoolean(String.valueOf(context.getProperty
                        (EmailOTPAuthenticatorConstants.IS_EMAILOTP_MANDATORY)));
                sendOtpToFederatedEmail = Boolean.parseBoolean(String.valueOf(context.getProperty
                        (EmailOTPAuthenticatorConstants.SEND_OTP_TO_FEDERATED_EMAIL_ATTRIBUTE)));
                usecase = (String) context.getProperty(EmailOTPAuthenticatorConstants.USE_CASE);
            }
            String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                    context.getCallerSessionKey(), context.getContextIdentifier());
            // This multi option URI is used to navigate back to multi option page to select a different
            // authentication option from Email OTP pages.
            String multiOptionURI = getMultiOptionURIQueryParam(request);
            if (StringUtils.isNotEmpty(multiOptionURI)) {
                queryParams += multiOptionURI;
            }

            // If 'usecase' property is not configured for email OTP authenticator, the below flow will be executed
            // (Recommended flow)
            if (StringUtils.isEmpty(usecase)) {
                Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
                Map<ClaimMapping, String> userAttributes = new HashMap<>();
                String federatedEmailAttributeKey = null;
                String username = null;
                boolean isLocalUser = false;
                // Iterate through the steps to identify from which step the user email address need to extracted
                for (StepConfig stepConfig : stepConfigMap.values()) {
                    authenticatedUser = stepConfig.getAuthenticatedUser();
                    if (authenticatedUser != null && isPreviousIdPAuthenticationFlowHandler(context)) {
                        authenticatedUser = resolveUserFromUserStore(authenticatedUser);
                    }
                    if (authenticatedUser != null && stepConfig.isSubjectAttributeStep()) {
                        username = authenticatedUser.toFullQualifiedUsername();
                        if (LOCAL_AUTHENTICATOR.equals(stepConfig.getAuthenticatedIdP())) {
                            isLocalUser = true;
                            break;
                        }
                        userAttributes = authenticatedUser.getUserAttributes();
                        federatedEmailAttributeKey = getFederatedEmailAttributeKey(context,
                                stepConfig.getAuthenticatedAutenticator().getName());
                        break;
                    }
                }

                if (username == null && isEmailOTPAsFirstFactor(context)) {
                    if (!(context.isRetrying()
                            && Boolean.parseBoolean(request.getParameter(EmailOTPAuthenticatorConstants.RESEND)))) {
                        context.setProperty(EmailOTPAuthenticatorConstants.CODE_MISMATCH, true);
                    }
                    redirectToEmailOTPLoginPage(response, request, context, emailOTPParameters, queryParams, null);
                    return;
                } else if (username == null) {
                    log.debug("Cannot find the subject attributed step with authenticated user.");
                    throw new AuthenticationFailedException
                            ("Authentication failed. Cannot find the subject attributed step with authenticated user.");
                }

                // Set authenticatedUser prop into context which will used in checkEmailOTPBehaviour()
                context.setProperty(EmailOTPAuthenticatorConstants.AUTHENTICATED_USER, authenticatedUser);

                if (isLocalUser) {
                    handleEmailOTPForLocalUser(username, authenticatedUser, context, emailOTPParameters,
                            isEmailOTPMandatory, queryParams, request, response);

                } else {
                    handleEmailOTPForFederatedUser(sendOtpToFederatedEmail, isEmailOTPMandatory, context,
                            userAttributes, federatedEmailAttributeKey, authenticatedUser, username,
                            queryParams, request, response);
                }

            } else {
                // If the attribute 'usecase' is configured, this block will be executed.
                // This block need to be revised and recommended to be removed

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
                            ("Authentication failed!. Cannot find the authenticated user, the username : " + username +
                                    " may be null");
                }

                boolean isUserExistence = FederatedAuthenticatorUtil.isUserExistInUserStore(username);

                if (isEmailOTPMandatory) {
                    if (log.isDebugEnabled()) {
                        log.debug("Process the EmailOTP mandatory flow ");
                    }
                    processEmailOTPMandatory(context, request, response, isUserExistence, username, queryParams,
                            emailOTPParameters, sendOtpToFederatedEmail);

                } else if (isUserExistence && !isEmailOTPDisableForUser(username, context,
                        emailOTPParameters)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Process the EmailOTP optional flow, because email OTP is enabled for the user " +
                                username);
                    }

                    email = getEmailForLocalUser(username, context, emailOTPParameters, queryParams, request, response);

                    if (StringUtils.isNotEmpty(email)) {
                        processEmailOTPFlow(request, response, email, username, queryParams, context);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Process with the first step (basic) authenticator only for user " + username);
                    }
                    processFirstStepOnly(authenticatedUser, context);
                }
            }

        } catch (EmailOTPException e) {
            throw new AuthenticationFailedException("Failed to get the email claim when proceed the EmailOTP flow ", e);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to get the user from user store ", e);
        }
    }

    /**
     * Process the response of the EmailOTP end-point.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(context);
        // Set isOTPExpired property to false initially in the context whenever the authentication response is received.
        context.setProperty(EmailOTPAuthenticatorConstants.OTP_EXPIRED, "false");
        boolean isLocalUser = isLocalUser(context);
        if (authenticatedUser == null) {
            String errorMessage = "Could not find an Authenticated user in the context.";
            throw new AuthenticationFailedException(errorMessage);
        }

        if (isLocalUser && EmailOTPUtils.isAccountLocked(authenticatedUser)) {
            String errorMessage =
                    String.format("Authentication failed since authenticated user: %s, account is locked.",
                            authenticatedUser);
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new AuthenticationFailedException(errorMessage);
        }

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
        long generatedTime = (long) context.getProperty(EmailOTPAuthenticatorConstants.OTP_GENERATED_TIME);
        boolean isExpired = isExpired(generatedTime, context);

        /*
        Before proceeding further if the the email update is already failed in the last attempt it will be set to false.
        */
        if (context.getProperty(EmailOTPAuthenticatorConstants.EMAIL_UPDATE_FAILURE) != null) {
            context.setProperty(EmailOTPAuthenticatorConstants.EMAIL_UPDATE_FAILURE, "false");
        }
        boolean succeededAttempt = false;
        if (userToken.equals(contextToken) && !isExpired) {
            context.setProperty(EmailOTPAuthenticatorConstants.CODE_MISMATCH, false);
            processValidUserToken(context, authenticatedUser);
            succeededAttempt = true;
        } else if (isBackupCodeEnabled(context)) {
            succeededAttempt = validateWithBackUpCodes(context, userToken, authenticatedUser);
        }

        /*
        If the email address of the user is not saved in the user's profile below code will be extracting the validated
        email address from the context and save it in user's profile. If saving failed it will save a property in the
        message context.
        */
        if (succeededAttempt && isLocalUser) {
            String username = authenticatedUser.toFullQualifiedUsername();
            String userEmail;
            try {
                userEmail = getEmailValueForUsername(username, context);
            } catch (EmailOTPException e) {
                throw new AuthenticationFailedException("Failed to get the email claim for user " + username +
                        " for tenant " + context.getTenantDomain(), e);
            }

            if (StringUtils.isBlank(userEmail)) {
                if (log.isDebugEnabled()) {
                    log.debug("User profile doesn't contain the email address. Updating the verified email " +
                            "address for user " + username);
                }
                Object verifiedEmailObject = context.getProperty(EmailOTPAuthenticatorConstants.REQUESTED_USER_EMAIL);
                if (verifiedEmailObject != null) {
                    try {
                        updateEmailAddressForUsername(context, username);
                    } catch (UserStoreClientException e) {
                        context.setProperty(EmailOTPAuthenticatorConstants.EMAIL_UPDATE_FAILURE, "true");
                        throw new AuthenticationFailedException("Email claim update failed for user " + username,
                                e.getCause());
                    } catch (UserStoreException e) {
                        Throwable ex = e.getCause();
                        if (ex instanceof UserStoreClientException) {
                            context.setProperty(EmailOTPAuthenticatorConstants.EMAIL_UPDATE_FAILURE, "true");
                            context.setProperty(EmailOTPAuthenticatorConstants.PROFILE_UPDATE_FAILURE_REASON,
                                    ex.getMessage());
                        }
                        throw new AuthenticationFailedException("Email claim update failed for user " + username,
                                e.getCause());
                    }
                }
            }
        }

        if (!succeededAttempt) {
            handleOtpVerificationFail(context);
            if (isExpired) {
                if (log.isDebugEnabled()) {
                    log.debug("Given otp code is expired.");
                }
                context.setProperty(EmailOTPAuthenticatorConstants.OTP_EXPIRED, "true");
                throw new AuthenticationFailedException("OTP code has expired.");
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Given otp code is a mismatch.");
                }
                context.setProperty(EmailOTPAuthenticatorConstants.CODE_MISMATCH, true);
                throw new AuthenticationFailedException("Invalid code. Verification failed.");
            }
        }
        // It reached here means the authentication was successful.
        resetOtpFailedAttempts(context);
    }

    /**
     * Process valid user token.
     *
     * @param context           AuthenticationContext.
     * @param authenticatedUser AuthenticatedUser.
     */
    private void processValidUserToken(AuthenticationContext context, AuthenticatedUser authenticatedUser) {

        context.setProperty(EmailOTPAuthenticatorConstants.OTP_TOKEN, StringUtils.EMPTY);
        context.setProperty(EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN, StringUtils.EMPTY);
        context.setSubject(authenticatedUser);
    }

    /**
     * Check whether the entered code matches with a backup code.
     *
     * @param context           The AuthenticationContext.
     * @param userToken         The userToken.
     * @param authenticatedUser The authenticatedUser.
     * @return True if the user entered code matches with a backup code.
     * @throws AuthenticationFailedException If an error occurred while retrieving user claim for OTP list.
     */
    private boolean validateWithBackUpCodes(AuthenticationContext context, String userToken,
                                            AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        boolean isMatchingToken = false;
        String[] savedOTPs = null;
        String username = authenticatedUser.toFullQualifiedUsername();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        UserRealm userRealm = getUserRealm(username);
        try {
            if (userRealm == null) {
                throw new AuthenticationFailedException("UserRealm is null for user : " + username);
            }
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager != null) {
                String savedOTPString = userStoreManager
                        .getUserClaimValue(tenantAwareUsername,
                                EmailOTPAuthenticatorConstants.OTP_BACKUP_CODES_CLAIM, null);
                if (StringUtils.isNotEmpty(savedOTPString)) {
                    savedOTPs = savedOTPString.split(EmailOTPAuthenticatorConstants.BACKUP_CODES_SEPARATOR);
                }
            }

            // Check whether there is any backup OTPs and return.
            if (ArrayUtils.isEmpty(savedOTPs)) {
                if (log.isDebugEnabled()) {
                    log.debug("The claim " + EmailOTPAuthenticatorConstants.OTP_BACKUP_CODES_CLAIM + " does " +
                            "not contain any values.");
                }
                return false;
            }
            if (isBackUpCodeValid(savedOTPs, userToken)) {
                if (log.isDebugEnabled()) {
                    log.debug("Found saved backup Email OTP for user :" + username);
                }
                isMatchingToken = true;
                context.setSubject(authenticatedUser);
                savedOTPs = (String[]) ArrayUtils.removeElement(savedOTPs, userToken);
                if (log.isDebugEnabled()) {
                    log.debug("Removed backup code :" + userToken + " from saved backup codes list.");
                }
                userRealm.getUserStoreManager().setUserClaimValue(tenantAwareUsername,
                        EmailOTPAuthenticatorConstants.OTP_BACKUP_CODES_CLAIM,
                        String.join(EmailOTPAuthenticatorConstants.BACKUP_CODES_SEPARATOR, savedOTPs),
                        null);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("User entered OTP :" + userToken + " does not match with any of the saved " +
                            "backup codes.");
                }
                context.setProperty(EmailOTPAuthenticatorConstants.CODE_MISMATCH, true);
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Cannot find the user claim for OTP list for user : " +
                    username, e);
        }
        return isMatchingToken;
    }

    /**
     * Validates the usertoken from the saved backup otp codes.
     *
     * @param savedOTPs Array of saveOTPs.
     * @param userToken Usertoken.
     * @return True if the backup is valid, else returns false.
     */
    private boolean isBackUpCodeValid(String[] savedOTPs, String userToken) {

        // Check whether the usertoken exists in the saved backup OTP list.
        for (String value : savedOTPs) {
            if (value.equals(userToken)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns whether backup code is enabled.
     *
     * @param context AuthenticationContext
     * @return true if backup code is enabled, else returns false.
     */
    private boolean isBackupCodeEnabled(AuthenticationContext context) {

        return isLocalUser(context) && StringUtils
                .equals("true", EmailOTPUtils.getConfiguration(context, EmailOTPAuthenticatorConstants.BACKUP_CODE));
    }

    /**
     * Returns AuthenticatedUser object from context.
     *
     * @param context AuthenticationContext.
     * @return AuthenticatedUser
     */
    private AuthenticatedUser getAuthenticatedUser(AuthenticationContext context) {

        AuthenticatedUser authenticatedUser = null;
        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        for (StepConfig stepConfig : stepConfigMap.values()) {
            AuthenticatedUser authenticatedUserInStepConfig = stepConfig.getAuthenticatedUser();
            if (stepConfig.isSubjectAttributeStep() && authenticatedUserInStepConfig != null) {
                authenticatedUser = new AuthenticatedUser(stepConfig.getAuthenticatedUser());
                break;
            }
        }
        if (context.getLastAuthenticatedUser() != null && context.getLastAuthenticatedUser().getUserName() != null) {
            authenticatedUser = context.getLastAuthenticatedUser();
        }
        return authenticatedUser;
    }

    /**
     * Checks whether email API or via SMTP protocol is used to send OTP to email.
     *
     * @param context                 the authentication context
     * @param emailOTPParameters      EmailOTP Parameters
     * @param authenticatorProperties the authenticator properties
     * @param email                   the email value to send OTP
     * @param username                username according to the use case
     * @param myToken                 the token
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void checkEmailOTPBehaviour(AuthenticationContext context, Map<String, String> emailOTPParameters,
                                        Map<String, String> authenticatorProperties, String email, String username,
                                        String myToken, String ipAddress) throws AuthenticationFailedException {

        if (isSMTP(authenticatorProperties, emailOTPParameters, context)) {
            // Check whether the authenticator is configured to use the event handler implementation.
            if (emailOTPParameters.get(EmailOTPAuthenticatorConstants.USE_EVENT_HANDLER_BASED_EMAIL_SENDER) != null
                    && Boolean.parseBoolean(emailOTPParameters.get(
                    EmailOTPAuthenticatorConstants.USE_EVENT_HANDLER_BASED_EMAIL_SENDER))) {
                AuthenticatedUser authenticatedUser = (AuthenticatedUser) context.getProperty
                        (EmailOTPAuthenticatorConstants.AUTHENTICATED_USER);
                if (authenticatedUser == null) {
                    throw new AuthenticationFailedException("Error occurred while triggering notification." +
                            " Unable to find authenticated user.");
                }

                // Check whether the authenticator is configured to pass the service provider name to event framework.
                Map<String, String> metaProperties = new HashMap<>();
                if (Boolean.parseBoolean(emailOTPParameters.get(
                        EmailOTPAuthenticatorConstants.PASS_SP_NAME_TO_EVENT))) {
                    metaProperties.put(EmailOTPAuthenticatorConstants.SERVICE_PROVIDER_NAME,
                            context.getServiceProviderName());
                }
                triggerEvent(authenticatedUser, myToken, email, metaProperties);
            } else {
                sendOTP(username, myToken, email, context, ipAddress);
            }
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
     * Get new authenticator properties with the accessToken response if emailApi used to send OTP.
     *
     * @param context                 the authentication context
     * @param emailOTPParameters      EmailOTP Parameters
     * @param authenticatorProperties the authenticator properties
     * @return authenticatorProperties by appending the token response
     * @throws AuthenticationFailedException If an error occurred.
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
     * Get federated authenticator key of email attribute (email or specific claim dialect for email attribute).
     *
     * @param context           the authentication context
     * @param authenticatorName the authenticator name
     * @return the key of federatedEmailAttribute
     * @throws AuthenticationFailedException If an error occurred.
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
     * Check EmailOTP Mandatory case.
     *
     * @param context                        the AuthenticationContext
     * @param request                        the HttpServletRequest
     * @param response                       the HttpServletResponse
     * @param isUserExistence                check userExistence
     * @param username                       the username
     * @param queryParams                    the queryParams
     * @param emailOTPParameters             the emailotp parameters
     * @param sendOtpToFederatedEmailAddress check otp directly send to federated email attribute is enable or not
     * @throws EmailOTPException             If an error occurred.
     * @throws AuthenticationFailedException If an error occurred.
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
                    String requestEmail = request.getParameter(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS);
                    if (StringUtils.isBlank(requestEmail) && (isOTPMismatched(context) || isOTPExpired(context))
                            && !isEmailUpdateFailed(context)) {
                        if (log.isDebugEnabled()) {
                            log.debug("Retrieving user email address from message context due to OTP mismatch or " +
                                    "OTP expire scenario for user " + username);
                        }
                        email = String.valueOf(
                                context.getProperty(EmailOTPAuthenticatorConstants.REQUESTED_USER_EMAIL));
                    } else if (StringUtils.isBlank(requestEmail)) {
                        redirectToEmailAddressReqPage(response, context, emailOTPParameters, queryParams, username);
                    } else {
                        context.setProperty(EmailOTPAuthenticatorConstants.REQUESTED_USER_EMAIL, requestEmail);
                        email = requestEmail;
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
     * @param username the Username
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void updateEmailAddressForUsername(AuthenticationContext context, String username)
            throws AuthenticationFailedException, UserStoreException {

        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        Map<String, String> attributes = new HashMap<>();
        attributes.put(EmailOTPAuthenticatorConstants.EMAIL_CLAIM,
                String.valueOf(context.getProperty(EmailOTPAuthenticatorConstants.REQUESTED_USER_EMAIL)));
        updateUserAttribute(MultitenantUtils.getTenantAwareUsername(username), attributes, tenantDomain);
    }

    /**
     * Update the email address (user attribute) in user's profile.
     *
     * @param username  the Username
     * @param attribute the Attribute
     */
    private void updateUserAttribute(String username, Map<String, String> attribute, String tenantDomain)
            throws AuthenticationFailedException, UserStoreException {

        try {
            /*
            Updating user attributes is independent from tenant association.not tenant association check needed here.
            User is always in the super tenant.
             */
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
            if (userRealm == null) {
                throw new AuthenticationFailedException("The specified tenant domain " + tenantDomain
                        + " does not exist.");
            }
            // Check whether user already exists in the system.
            verifyUserExists(username, tenantDomain);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            userStoreManager.setUserClaimValues(username, attribute, null);
        } catch (AuthenticationFailedException e) {
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
            String emailAddressReqPage = getRequestEmailPageUrl(context, emailOTPParameters);
            try {
                String url = getRedirectURL(emailAddressReqPage, queryParams);
                if (isEmailUpdateFailed(context)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Updating email address has failed for user " + username + ". " +
                                "Redirecting user to email address capturing page");
                    }
                    url = FrameworkUtils.appendQueryParamsStringToUrl(url, EmailOTPAuthenticatorConstants.RETRY_PARAMS);
                    if (context.getProperty(EmailOTPAuthenticatorConstants.PROFILE_UPDATE_FAILURE_REASON) != null) {
                        String failureReason = String.valueOf(
                                context.getProperty(EmailOTPAuthenticatorConstants.PROFILE_UPDATE_FAILURE_REASON));
                        String updateFailureReasonQueryParam = EmailOTPAuthenticatorConstants.ERROR_MESSAGE_DETAILS +
                                URLEncoder.encode(failureReason, StandardCharsets.UTF_8.name());
                        url = FrameworkUtils.appendQueryParamsStringToUrl(url, updateFailureReasonQueryParam);
                    }
                }
                response.sendRedirect(url);
            } catch (IOException e) {
                throw new AuthenticationFailedException("Authentication failed!. An IOException was caught while " +
                        "redirecting to email address request page. ", e);
            }
        } else {
            String msg = "Authentication failed!. Email address unavailable for user and option to update email " +
                    "address during login is not enabled. Update email address for the user : " + username;
            throw new AuthenticationFailedException(msg);
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
     * In EmailOTP mandatory case, If user not found in the directory then send otp directly to federated email.
     *
     * @param context                 the AuthenticationContext
     * @param request                 the HttpServletRequest
     * @param response                the HttpServletResponse
     * @param username                the username
     * @param queryParams             the queryParams
     * @param sendOtpToFederatedEmail check whether directly send otp federated email attribute is enable or not
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void proceedOTPWithFederatedEmailAddress(AuthenticationContext context, HttpServletRequest request,
                                                     HttpServletResponse response, String username, String queryParams,
                                                     boolean sendOtpToFederatedEmail,
                                                     Map<String, String> emailOTPParameters)
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
     * In EmailOTP optional case, If uer not found or email claim doesn't enable then process the first step only.
     *
     * @param authenticatedUser the authenticatedUser
     * @param context           the AuthenticationContext
     */
    private void processFirstStepOnly(AuthenticatedUser authenticatedUser, AuthenticationContext context) {

        // The authentication flow happens with basic authentication (First step only).
        StepConfig stepConfig = context.getSequenceConfig().getStepMap().get(context.getCurrentStep() - 1);
        if (stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator() instanceof
                LocalApplicationAuthenticator) {
            FederatedAuthenticatorUtil.updateLocalAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(EmailOTPAuthenticatorConstants.AUTHENTICATION, EmailOTPAuthenticatorConstants.BASIC);
        } else {
            FederatedAuthenticatorUtil.updateAuthenticatedUserInStepConfig(context, authenticatedUser);
            context.setProperty(EmailOTPAuthenticatorConstants.AUTHENTICATION,
                    EmailOTPAuthenticatorConstants.FEDERETOR);
        }
    }

    /**
     * To redirect flow to error page with specific condition.
     *
     * @param response           the httpServletResponse
     * @param context            the AuthenticationContext
     * @param emailOTPParameters the emailotp parameters
     * @param queryParams        the query params
     * @param retryParam         the retry param
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void redirectToErrorPage(HttpServletResponse response, AuthenticationContext context,
                                     Map<String, String> emailOTPParameters, String queryParams, String retryParam)
            throws AuthenticationFailedException {

        try {
            // Full url of the error page.
            String errorPage = getEmailOTPErrorPageUrl(context, emailOTPParameters);
            String url = getRedirectURL(errorPage, queryParams);
            response.sendRedirect(url + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Authentication Failed : An IO Exception caught," +
                    " While redirecting to error page ", e);
        }
    }

    /**
     * Process the EmailOTP Flow.
     *
     * @param request     the request
     * @param response    response
     * @param email       value of the email to send otp
     * @param username    the username
     * @param queryParams the queryParams
     * @param context     the authentication context
     * @throws AuthenticationFailedException If an error occurred.
     */
    protected void processEmailOTPFlow(HttpServletRequest request, HttpServletResponse response, String email,
                                       String username, String queryParams,
                                       AuthenticationContext context) throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        Map<String, String> emailOTPParameters = getAuthenticatorConfig().getParameterMap();
        boolean showAuthFailureReason =
                Boolean.parseBoolean(emailOTPParameters.get(EmailOTPAuthenticatorConstants.SHOW_AUTH_FAILURE_REASON));
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(context);
        try {
            if (isLocalUser(context) && EmailOTPUtils.isAccountLocked(authenticatedUser)) {
                String retryParam;
                if (showAuthFailureReason) {
                    long unlockTime = getUnlockTimeInMilliSeconds(authenticatedUser);
                    long timeToUnlock = unlockTime - System.currentTimeMillis();
                    if (timeToUnlock > 0) {
                        queryParams += "&unlockTime=" + Math.round((double) timeToUnlock / 1000 / 60);
                    }
                    retryParam = EmailOTPAuthenticatorConstants.ERROR_USER_ACCOUNT_LOCKED;
                    // Locked reason.
                    String lockedReason = getLockedReason(authenticatedUser);
                    if (StringUtils.isNotBlank(lockedReason)) {
                        queryParams += "&lockedReason=" + lockedReason;
                    }
                    queryParams += "&errorCode=" + UserCoreConstants.ErrorCode.USER_IS_LOCKED;
                } else {
                    retryParam = EmailOTPAuthenticatorConstants.RETRY_PARAMS;
                }
                redirectToErrorPage(response, context, emailOTPParameters, queryParams, retryParam);
                return;
            }
            if (!context.isRetrying()
                    || (context.isRetrying()
                    && Boolean.parseBoolean(request.getParameter(EmailOTPAuthenticatorConstants.RESEND)))
                    || (context.isRetrying() && !isOTPResendingDisabledOnFailure(context) && isOTPExpired(context))
                    || (context.isRetrying() && isEmailUpdateFailed(context))) {

                boolean isCharInOTP = !Boolean.parseBoolean(authenticatorProperties
                        .get(EmailOTPAuthenticatorConstants.EMAIL_OTP_NUMERIC_OTP));
                context.setProperty(EmailOTPAuthenticatorConstants.IS_CHAR_IN_OTP, isCharInOTP);

                int expiryTime = getEmailOTPExpiryTime(authenticatorProperties);
                context.setProperty(EmailOTPAuthenticatorConstants.TOKEN_EXPIRE_TIME_IN_MILIS,
                        Integer.toString(expiryTime));

                int numOfDigitsInOTP = getEmailOTPLength(authenticatorProperties);
                context.setProperty(EmailOTPAuthenticatorConstants.EMAIL_OTP_LENGTH, numOfDigitsInOTP);

                String myToken = generateOTP(context);

                String ipAddress = IdentityUtil.getClientIpAddress(request);
                context.setProperty(EmailOTPAuthenticatorConstants.OTP_TOKEN, myToken);
                context.setProperty(EmailOTPAuthenticatorConstants.OTP_GENERATED_TIME, System.currentTimeMillis());
                if (StringUtils.isNotEmpty(myToken)) {
                    checkEmailOTPBehaviour(context, emailOTPParameters, authenticatorProperties, email, username,
                            myToken, ipAddress);
                } else {
                    throw new AuthenticationFailedException(
                            "Error while retrieving properties. Authenticator Properties cannot be null");
                }
            }
            if (context.isRetrying()
                    || !Boolean.parseBoolean(request.getParameter(EmailOTPAuthenticatorConstants.RESEND))) {
                redirectToEmailOTPLoginPage(response, request, context, emailOTPParameters, queryParams, email);
            }
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException("Authentication Failed: Authenticator Properties may be null ", e);
        }
    }

    private int getEmailOTPLength(Map<String, String> authenticatorProperties) {

        int numOfDigitsInOTP = EmailOTPAuthenticatorConstants.NUMBER_DIGIT;
        if (StringUtils.isNotEmpty(
                authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAIL_OTP_LENGTH))) {
            int numDigitsInProperties = Integer.parseInt(authenticatorProperties
                    .get(EmailOTPAuthenticatorConstants.EMAIL_OTP_LENGTH));
            if (numDigitsInProperties >= EmailOTPAuthenticatorConstants.EMAIL_OTP_MIN_LENGTH
                    && numDigitsInProperties <= EmailOTPAuthenticatorConstants.EMAIL_OTP_MAX_LENGTH) {
                numOfDigitsInOTP = numDigitsInProperties;
            }
        }
        return numOfDigitsInOTP;
    }

    private int getEmailOTPExpiryTime(Map<String, String> authenticatorProperties) {

        int expiryTime = Integer.parseInt(EmailOTPAuthenticatorConstants.OTP_EXPIRE_TIME_DEFAULT);
        if (StringUtils.isNotEmpty(
                authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAIL_OTP_EXPIRY_TIME))) {
            int expiryTimeInMinutes = Integer.parseInt(authenticatorProperties
                    .get(EmailOTPAuthenticatorConstants.EMAIL_OTP_EXPIRY_TIME));
            if (expiryTimeInMinutes <= EmailOTPAuthenticatorConstants.EMAIL_OTP_MAX_EXPIRY_TIME
                    && expiryTimeInMinutes >= EmailOTPAuthenticatorConstants.EMAIL_OTP_MIN_EXPIRY_TIME) {
                expiryTime = expiryTimeInMinutes * 60 * 1000;
            }
        }
        return expiryTime;
    }

    /**
     * Get MultiOptionURI query parameter from the request.
     * @param request Http servlet request.
     * @return MultiOptionURI query parameter.
     */
    private String getMultiOptionURIQueryParam(HttpServletRequest request) {

        if (request != null) {
            String multiOptionURI = request.getParameter(EmailOTPAuthenticatorConstants.MULTI_OPTION_URI);
            if (StringUtils.isNotEmpty(multiOptionURI)) {
                return "&" + EmailOTPAuthenticatorConstants.MULTI_OPTION_URI + "="
                        + Encode.forUriComponent(multiOptionURI);
            }
        }
        return StringUtils.EMPTY;
    }

    /**
     * To redirect the flow to email otp login page to enter an OTP.
     *
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void redirectToEmailOTPLoginPage(HttpServletResponse response, HttpServletRequest request,
                                             AuthenticationContext context, Map<String, String> emailOTPParameters,
                                             String queryParams, String email) throws AuthenticationFailedException {

        try {
            // Full url of the login page
            String emailOTPLoginPage = getEmailOTPLoginPageUrl(context, emailOTPParameters);
            String url = getRedirectURL(emailOTPLoginPage, queryParams);
            if (email != null && isShowEmailAddressInUIEnable(context, emailOTPParameters)) {
                String emailAddressRegex = getEmailAddressRegex(context, emailOTPParameters);
                if (StringUtils.isNotEmpty(emailAddressRegex)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Email address regex defined. Masking the email address using the regex.");
                    }
                    email = email.replaceAll(emailAddressRegex, "*");
                } else if (log.isDebugEnabled()) {
                    log.debug("Email address regex not set. Showing the complete email address.");
                }
                url = url + EmailOTPAuthenticatorConstants.SCREEN_VALUE + email;
            }
            if (context.isRetrying()
                    && !Boolean.parseBoolean(request.getParameter(EmailOTPAuthenticatorConstants.RESEND))
                    && !isEmailUpdateFailed(context)) {
                // Build redirect url by validating whether the otp has been expired or not.
                if (isOTPExpired(context)) {
                    // Differentiating the error message according to the config disableOTPResendOnFailure.
                    if (isOTPResendingDisabledOnFailure(context)) {
                        url = url + EmailOTPAuthenticatorConstants.ERROR_TOKEN_EXPIRED;
                    } else {
                        url = url + EmailOTPAuthenticatorConstants.ERROR_TOKEN_EXPIRED_EMAIL_SENT;
                    }
                } else {
                    url = url + EmailOTPAuthenticatorConstants.RETRY_PARAMS;
                }
            }
            url += getCaptchaParams(request, context);
            context.setProperty(EmailOTPAuthenticatorConstants.IS_REDIRECT_TO_EMAIL_OTP, "true");
            response.sendRedirect(url);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Authentication Failed: An IOException was caught while " +
                    "redirecting to login page. ", e);
        }
    }

    /**
     * Send REST call.
     */
    private String sendRESTCall(String url, String urlParameters, String accessToken, String formParameters
            , String payload, String httpMethod) {

        String line;
        StringBuilder responseString = new StringBuilder();
        HttpURLConnection connection = null;
        try {
            URL emailOTPEP = new URL(url + urlParameters);
            URLConnection urlConnection = emailOTPEP.openConnection();
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
                log.debug(EmailOTPAuthenticatorConstants.FAILED + " An IOException occurred while perform a " +
                        "rest call with API endpoint ", e);
            }
            return EmailOTPAuthenticatorConstants.FAILED;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
        return responseString.toString();
    }

    /**
     * Prepare the payload to send otp via API's.
     *
     * @param context                 the AuthenticationContext
     * @param authenticatorProperties the authenticatorProperties
     * @param emailOTPParameters      the emailOTPParameters
     * @param email                   the email address to send otp
     * @param otp                     the one time password
     * @return the payload
     */
    private String preparePayload(AuthenticationContext context, Map<String, String> authenticatorProperties,
                                  Map<String, String> emailOTPParameters, String email, String otp) {

        String payload;
        String api = getAPI(authenticatorProperties);
        if (api.equals(EmailOTPAuthenticatorConstants.API_GMAIL)) {
            payload = "to:" + email + "\n" +
                    "subject:OTP Code\n" +
                    "from:" + authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL) + "\n\n" +
                    otp;
            payload = "{\"raw\":\"" + Base64.encode(payload.getBytes()) + "\"}";
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
     * Prepare the required URL params to send otp via API's.
     *
     * @param context                 the AuthenticationContext
     * @param authenticatorProperties the authenticatorProperties
     * @param emailOTPParameters      the emailOTPParameters
     * @return the urlParams
     */
    private String prepareURLParams(AuthenticationContext context, Map<String, String> authenticatorProperties,
                                    Map<String, String> emailOTPParameters) {

        String api = getAPI(authenticatorProperties);
        String urlParams = getPrepareURLParams(context, emailOTPParameters, api);
        return StringUtils.isNotEmpty(urlParams) ? urlParams : null;
    }

    /**
     * Prepare the required form data to send otp via API's.
     *
     * @param context                 the AuthenticationContext
     * @param authenticatorProperties the authenticatorProperties
     * @param emailOTPParameters      the emailOTPParameters
     * @param email                   the email address to send otp
     * @param otp                     the one time password
     * @return the formData
     */
    private String prepareFormData(AuthenticationContext context, Map<String, String> authenticatorProperties,
                                   Map<String, String> emailOTPParameters, String email, String otp) {

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
     * Check Which api need access token.
     *
     * @param context                 the AuthenticationContext
     * @param emailOTPParameters      the emailOTPParameters
     * @param authenticatorProperties the authenticatorProperties
     * @return true or false
     */
    private boolean isAccessTokenRequired(AuthenticationContext context, Map<String, String> emailOTPParameters,
                                          Map<String, String> authenticatorProperties) {

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
     * Check which api need apiKey as a header.
     *
     * @param context                 the AuthenticationContext
     * @param emailOTPParameters      the emailOTPParameters
     * @param authenticatorProperties the authenticatorProperties
     * @return true or false
     */
    private boolean isAPIKeyHeaderRequired(AuthenticationContext context, Map<String, String> emailOTPParameters,
                                           Map<String, String> authenticatorProperties) {

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
     * Check whether EmailOTP is disabled for user.
     *
     * @param authenticatedUser authenticated user
     * @param context           authentication context
     * @param parametersMap     parameter map
     * @return if the email otp is disabled for user
     *
     * @throws AuthenticationFailedException
     */
    private boolean isEmailOTPDisableForUser(AuthenticatedUser authenticatedUser, AuthenticationContext context,
                                             Map<String, String> parametersMap)
            throws AuthenticationFailedException {

        UserRealm userRealm;
        try {
            int tenantId = IdentityTenantUtil.getTenantId(authenticatedUser.getTenantDomain());
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            if (userRealm != null) {
                if (isAdminMakeUserToEnableOrDisableEmailOTP(context, parametersMap)) {
                    AbstractUserStoreManager userStoreManager =
                            (AbstractUserStoreManager) userRealm.getUserStoreManager();
                    Map<String, String> claimValues
                            = userStoreManager.getUserClaimValuesWithID(authenticatedUser.getUserId(),
                            new String[]{EmailOTPAuthenticatorConstants.USER_EMAILOTP_DISABLED_CLAIM_URI}, null);
                    String isEmailOTPEnabledByUser = claimValues.
                            get(EmailOTPAuthenticatorConstants.USER_EMAILOTP_DISABLED_CLAIM_URI);
                    return Boolean.parseBoolean(isEmailOTPEnabledByUser);
                }
            } else {
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant domain : "
                        + authenticatedUser.getTenantDomain());
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed while trying to access userRealm of the user: "
                    + authenticatedUser.getLoggableUserId(), e);
        } catch (UserIdNotFoundException e) {
            throw new AuthenticationFailedException("Error while checking if the email OTP is enabled for the user: "
                    + authenticatedUser.getLoggableUserId(), e);
        }
        return false;
    }

    /**
     * Email OTP handled for local users.
     *
     * @param username            name of the user
     * @param authenticatedUser   {@link AuthenticatedUser} object of the authenticated user
     * @param context             {@link AuthenticationContext} object of the authentication request
     * @param emailOTPParameters  {@link Map} of email OTP authenticator specific parameters
     * @param isEmailOTPMandatory boolean value to identify whether email OTP is configured as mandatory or not
     * @param queryParams         extracted query parameters from the context
     * @param request             {@link HttpServletRequest}
     * @param response            {@link HttpServletResponse}
     * @throws AuthenticationFailedException when anything failed during handling email OTP for local user.
     */
    private void handleEmailOTPForLocalUser(String username, AuthenticatedUser authenticatedUser,
                                            AuthenticationContext context, Map<String, String> emailOTPParameters,
                                            boolean isEmailOTPMandatory, String queryParams,
                                            HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationFailedException {

        try {
            if (isEmailOTPDisableForUser(username, context, emailOTPParameters) && !isEmailOTPMandatory) {
                if (log.isDebugEnabled()) {
                    log.debug("Email OTP authentication is skipped for the user " + username +
                            ". Email OTP is not mandatory and disabled for the user.");
                }
                processFirstStepOnly(authenticatedUser, context);
            } else {
                String email = getEmailForLocalUser(username, context, emailOTPParameters, queryParams, request,
                        response);
                if (StringUtils.isNotEmpty(email)) {
                    processEmailOTPFlow(request, response, email, username, queryParams, context);

                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Email attribute is not available for the user " + username);
                    }
                }
            }
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException("Email OTP authentication failed for the local user " +
                    username, e);
        }
    }

    /**
     * Email OTP handled for federated users.
     *
     * @param sendOtpToFederatedEmail    boolean value to identify whether email OTP can be send to federated email
     * @param isEmailOTPMandatory        boolean value to identify whether email OTP is configured as mandatory or not
     * @param context                    {@link AuthenticationContext} object of the authentication request
     * @param userAttributes             {@link Map} with federated user attributes
     * @param federatedEmailAttributeKey used to identify the email value of federated authenticator
     * @param authenticatedUser          {@link AuthenticatedUser} object of the authenticated user
     * @param username                   name of the user
     * @param queryParams                extracted query parameters from the context
     * @param request                    {@link HttpServletRequest}
     * @param response                   {@link HttpServletResponse}
     * @throws AuthenticationFailedException when anything failed during handling email OTP for federated user.
     */
    private void handleEmailOTPForFederatedUser(boolean sendOtpToFederatedEmail, boolean isEmailOTPMandatory,
                                                AuthenticationContext context, Map<ClaimMapping, String> userAttributes,
                                                String federatedEmailAttributeKey, AuthenticatedUser authenticatedUser,
                                                String username, String queryParams, HttpServletRequest request,
                                                HttpServletResponse response)
            throws AuthenticationFailedException {

        try {
            if (sendOtpToFederatedEmail) {
                if (StringUtils.isEmpty(federatedEmailAttributeKey)) {
                    federatedEmailAttributeKey = getFederatedEmailAttributeKey(context, context.getSequenceConfig()
                            .getStepMap().get(context.getCurrentStep()).getAuthenticatorList().iterator().next()
                            .getName());
                }

                String email = getEmailForFederatedUser(userAttributes, federatedEmailAttributeKey);
                if (StringUtils.isEmpty(email)) {
                    if (isEmailOTPMandatory) {
                        if (log.isDebugEnabled()) {
                            log.debug("Email OTP authentication is failed for the federated user" + username +
                                    ". There is no email claim to send OTP and email OTP is mandatory.");
                        }
                        throw new AuthenticationFailedException("Email OTP authentication is failed for the " +
                                "federated user" + username + ". There is no email claim to send OTP and email OTP " +
                                "is mandatory.");
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("Email OTP authentication is skipped for the federated user " + username +
                                    ". There is no email claim to send OTP and email OTP is not mandatory.");
                        }
                        processFirstStepOnly(authenticatedUser, context);
                    }

                } else {
                    context.setProperty(EmailOTPAuthenticatorConstants.RECEIVER_EMAIL, email);
                    processEmailOTPFlow(request, response, email, username, queryParams, context);
                }

            } else if (isEmailOTPMandatory) {
                if (log.isDebugEnabled()) {
                    log.debug("Email OTP authentication is failed for federated user " + username + ". Send OTP to " +
                            "federated email is disabled.");
                }
                throw new AuthenticationFailedException("Email OTP authentication is failed for federated user "
                        + username + ". Send OTP to federated email is disabled.");

            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Email OTP authentication is skipped for federated user " + username + ". Send OTP to " +
                            "federated email is not enabled.");
                }
                processFirstStepOnly(authenticatedUser, context);
            }
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException("Email OTP authentication is failed for federated user " +
                    username, e);
        }
    }

    /**
     * Extract the email value for local user.
     *
     * @param username           name of the user
     * @param context            {@link AuthenticationContext} object of the authentication request
     * @param emailOTPParameters {@link Map} of email OTP authenticator specific parameters
     * @param queryParams        extracted query parameters from the context
     * @param request            {@link HttpServletRequest}
     * @param response           {@link HttpServletResponse}
     * @return the email attribute
     * @throws AuthenticationFailedException when anything failed during extracting email of local user.
     */
    private String getEmailForLocalUser(String username, AuthenticationContext context,
                                        Map<String, String> emailOTPParameters, String queryParams,
                                        HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationFailedException {

        String email;
        try {
            email = getEmailValueForUsername(username, context);
            if (StringUtils.isEmpty(email)) {
                String requestEmail = request.getParameter(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS);
                if (StringUtils.isBlank(requestEmail) && (isOTPMismatched(context) || isOTPExpired(context))
                        && !isEmailUpdateFailed(context)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Retrieving user email address from message context due to OTP mismatch or " +
                                "OTP expire scenario for user " + username);
                    }
                    email = String.valueOf(context.getProperty(EmailOTPAuthenticatorConstants.REQUESTED_USER_EMAIL));
                } else if (StringUtils.isBlank(requestEmail)) {
                    if (log.isDebugEnabled()) {
                        log.debug("email claim is not available for the user " + username);
                    }
                    redirectToEmailAddressReqPage(response, context, emailOTPParameters, queryParams,
                            username);
                } else {
                    context.setProperty(EmailOTPAuthenticatorConstants.REQUESTED_USER_EMAIL, requestEmail);
                    email = requestEmail;
                }
            }
        } catch (EmailOTPException | AuthenticationFailedException e) {
            throw new AuthenticationFailedException("Extracting email claim is failed for the local user " +
                    username, e);
        }
        return email;
    }

    /**
     * Extract the email value from federated user attributes.
     *
     * @param userAttributes             {@link Map} with federated user attributes
     * @param federatedEmailAttributeKey used to identify the email value of federated authenticator
     * @return the email attribute
     */
    private String getEmailForFederatedUser(Map<ClaimMapping, String> userAttributes,
                                            String federatedEmailAttributeKey) {

        String email = null;
        for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
            String key = String.valueOf(entry.getKey().getLocalClaim().getClaimUri());
            String value = entry.getValue();
            if (key.equals(federatedEmailAttributeKey)) {
                email = String.valueOf(value);
                break;
            }
        }
        return email;
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
     * Get email value for username.
     *
     * @param username the user name
     * @param context  the authentication context
     * @return email
     * @throws EmailOTPException If an error occurred.
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
     * Get clientId for Gmail APIs.
     */
    private String getClientId(AuthenticationContext context, Map<String, String> parametersMap, String api) {

        String clientId = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.CLIENT_ID)) {
            clientId = parametersMap.get(api + EmailOTPAuthenticatorConstants.CLIENT_ID);
        } else if ((context.getProperty(api + EmailOTPAuthenticatorConstants.CLIENT_ID)) != null) {
            clientId = String.valueOf(context.getProperty(api + EmailOTPAuthenticatorConstants.CLIENT_ID));
        }
        return clientId;
    }

    /**
     * Get clientSecret for Gmail APIs.
     */
    private String getClientSecret(AuthenticationContext context, Map<String, String> parametersMap, String api) {

        String clientSecret = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(api + EmailOTPAuthenticatorConstants.CLIENT_SECRET)) {
            clientSecret = parametersMap.get(api + EmailOTPAuthenticatorConstants.CLIENT_SECRET);
        } else if ((context.getProperty(api + EmailOTPAuthenticatorConstants.CLIENT_SECRET)) != null) {
            clientSecret = String.valueOf(context.getProperty(api + EmailOTPAuthenticatorConstants.CLIENT_SECRET));
        }
        return clientSecret;
    }

    /**
     * Get RefreshToken for Gmail APIs.
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
     * Get ApiKey for Gmail APIs.
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
     * Get MailingEndpoint for Gmail APIs.
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
     * Get required payload for Gmail APIs.
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
     * Get required FormData for Gmail APIs.
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
     * Get required URL params for Gmail APIs.
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
     * Get failureString for Gmail APIs.
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
     * Get AuthToken type for Gmail APIs.
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
     * Get AccessToken endpoint for Gmail APIs.
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

    /**
     * Get the email address regex pattern when we show the email address in UI where the otp is sent.
     *
     * @param context       the AuthenticationContext
     * @param parametersMap the parameter map
     * @return emailAddressRegex
     */
    private String getEmailAddressRegex(AuthenticationContext context, Map<String, String> parametersMap) {

        String emailAddressRegex = null;
        String tenantDomain = context.getTenantDomain();
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        if ((propertiesFromLocal != null || tenantDomain.equals(EmailOTPAuthenticatorConstants.SUPER_TENANT)) &&
                parametersMap.containsKey(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS_REGEX)) {
            emailAddressRegex = parametersMap.get(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS_REGEX);
            if (log.isDebugEnabled()) {
                log.debug("Getting the email address regex from parameters map: " + emailAddressRegex);
            }
        } else if ((context.getProperty(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS_REGEX)) != null) {
            emailAddressRegex = String.valueOf(context.getProperty(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS_REGEX));
            if (log.isDebugEnabled()) {
                log.debug("Getting the email address regex from the context: " + emailAddressRegex);
            }
        }
        return emailAddressRegex;
    }

    private String getAPI(Map<String, String> authenticatorProperties) {

        return StringUtils.trim(authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAIL_API));
    }

    /**
     * Send mail (otp) using email API's.
     *
     * @param context                 the AuthenticationContext
     * @param authenticatorProperties the authenticatorProperties
     * @param emailOTPParameters      the emailOTPParameters
     * @param urlParams               the required urlParams
     * @param payload                 the required payload
     * @param formData                the formData
     * @return the response
     */
    private String sendMailUsingAPIs(AuthenticationContext context, Map<String, String> authenticatorProperties,
                                     Map<String, String> emailOTPParameters, String urlParams,
                                     String payload, String formData) {

        String response;
        String api = getAPI(authenticatorProperties);
        String apiKey = getApiKey(context, emailOTPParameters, api);
        String endpoint = getMailingEndpoint(context, emailOTPParameters, api);
        if ((isAccessTokenRequired(context, emailOTPParameters, authenticatorProperties)
                && StringUtils.isEmpty(authenticatorProperties.get(
                EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN)))
                || (isAPIKeyHeaderRequired(context, emailOTPParameters, authenticatorProperties)
                && StringUtils.isEmpty(apiKey))) {
            if (log.isDebugEnabled()) {
                log.debug("Required param '" +
                        (isAccessTokenRequired(context, emailOTPParameters, authenticatorProperties)
                                ? EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN
                                : EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY) + "' cannot be null");
            }
            return null;
        } else if (isAccessTokenRequired(context, emailOTPParameters, authenticatorProperties)
                || isAPIKeyHeaderRequired(context, emailOTPParameters, authenticatorProperties)) {
            String tokenType = getAuthTokenType(context, emailOTPParameters, api);
            if (StringUtils.isNotEmpty(endpoint) && StringUtils.isNotEmpty(tokenType)) {
                response = sendRESTCall(endpoint.replace(EmailOTPAuthenticatorConstants.ADMIN_EMAIL
                        , authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL))
                        , StringUtils.isNotEmpty(urlParams) ? urlParams : ""
                        , tokenType + " " +
                                (isAccessTokenRequired(context, emailOTPParameters, authenticatorProperties) ?
                                        authenticatorProperties.get(
                                                EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN) : apiKey),
                        formData, payload, EmailOTPAuthenticatorConstants.HTTP_POST);
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
     * Proceed with token request with api endpoint.
     *
     * @param context                 the AuthenticationContext
     * @param authenticatorProperties the authenticatorProperties
     * @param emailOTPParameters      the emailOTPParameters
     * @return the token response
     */
    private String sendTokenRequest(AuthenticationContext context, Map<String, String> authenticatorProperties,
                                    Map<String, String> emailOTPParameters) {

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
            response = sendRESTCall(getTokenEndpoint(context, authenticatorProperties, emailOTPParameters),
                    "", "", formParams, ""
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
                                      Map<String, String> emailOTPParameters) {

        String api = getAPI(authenticatorProperties);
        String tokenEndpoint = getAccessTokenEndpoint(context, emailOTPParameters, api);
        return StringUtils.isNotEmpty(tokenEndpoint) ? tokenEndpoint : null;
    }

    /**
     * Send otp to email address via SMTP protocol.
     *
     * @param username the username
     * @param otp      the one time password
     * @param email    the email address to send otp
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void sendOTP(String username, String otp, String email, AuthenticationContext context, String ipAddress)
            throws AuthenticationFailedException {

        System.setProperty(EmailOTPAuthenticatorConstants.AXIS2, EmailOTPAuthenticatorConstants.AXIS2_FILE);
        try {
            ConfigurationContext configurationContext =
                    ConfigurationContextFactory.createConfigurationContextFromFileSystem(null, null);
            if (configurationContext.getAxisConfiguration().getTransportsOut()
                    .containsKey(EmailOTPAuthenticatorConstants.TRANSPORT_MAILTO)) {
                NotificationSender notificationSender = new NotificationSender();
                NotificationDataDTO notificationData = new NotificationDataDTO();
                Notification emailNotification;
                NotificationData emailNotificationData = new NotificationData();
                ConfigBuilder configBuilder = ConfigBuilder.getInstance();
                String tenantDomain = MultitenantUtils.getTenantDomain(username);
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                String emailTemplate;
                Config config;
                try {
                    config = configBuilder.loadConfiguration(ConfigType.EMAIL, StorageType.REGISTRY, tenantId);
                } catch (IdentityMgtConfigException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Error occurred while loading email templates for user : " + username, e);
                    }
                    throw new AuthenticationFailedException("Error occurred while loading email templates for user : "
                            + username, e);
                }
                emailNotificationData.setTagData(EmailOTPAuthenticatorConstants.CODE, otp);
                emailNotificationData.setTagData(EmailOTPAuthenticatorConstants.SERVICE_PROVIDER_NAME,
                        context.getServiceProviderName());
                emailNotificationData.setTagData(EmailOTPAuthenticatorConstants.USER_NAME, username);
                emailNotificationData.setTagData(EmailOTPAuthenticatorConstants.IP_ADDRESS, ipAddress);
                emailNotificationData.setSendTo(email);
                if (config.getProperties().containsKey(EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME)) {
                    emailTemplate = config.getProperty(EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
                    try {
                        emailNotification = NotificationBuilder.createNotification("EMAIL",
                                emailTemplate, emailNotificationData);
                    } catch (IdentityMgtServiceException e) {
                        if (log.isDebugEnabled()) {
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
     * Check whether SMTP protocol is used or email api is used to send otp to an email account.
     *
     * @param authenticatorProperties the authenticatorProperties
     * @param emailOTPParameters      the emailOTPParameters
     * @param context                 the AuthenticationContext
     * @return true or false
     */
    private boolean isSMTP(Map<String, String> authenticatorProperties, Map<String, String> emailOTPParameters,
                           AuthenticationContext context) {

        String api = getAPI(authenticatorProperties);
        String mailingEndpoint = getMailingEndpoint(context, emailOTPParameters, api);
        String apiKey = getApiKey(context, emailOTPParameters, api);
        String refreshToken = getRefreshToken(context, emailOTPParameters, api);
        String clientId = getClientId(context, emailOTPParameters, api);
        String clientSecret = getClientSecret(context, emailOTPParameters, api);
        String email = authenticatorProperties.get(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL);
        return StringUtils.isEmpty(email) || StringUtils.isEmpty(api) || StringUtils.isEmpty(mailingEndpoint)
                || (!isAccessTokenRequired(context, emailOTPParameters, authenticatorProperties) &&
                StringUtils.isEmpty(apiKey))
                || (isAccessTokenRequired(context, emailOTPParameters, authenticatorProperties)
                && (StringUtils.isEmpty(refreshToken) || StringUtils.isEmpty(clientId)
                || StringUtils.isEmpty(clientSecret)));
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter("sessionDataKey");
    }

    /**
     * Get the friendly name of the Authenticator.
     */
    @Override
    public String getFriendlyName() {

        return EmailOTPAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator.
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
     * Get Configuration Properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();
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

        Property lengthOTP = new Property();
        lengthOTP.setName(EmailOTPAuthenticatorConstants.EMAIL_OTP_LENGTH);
        lengthOTP.setDisplayName("Email OTP length");
        lengthOTP.setDescription("The number of allowed characters in the OTP. Please pick a value between 4-10.");
        lengthOTP.setDefaultValue(Integer.toString(EmailOTPAuthenticatorConstants.NUMBER_DIGIT));
        lengthOTP.setDisplayOrder(2);
        configProperties.add(lengthOTP);

        Property expiryTimeOTP = new Property();
        expiryTimeOTP.setName(EmailOTPAuthenticatorConstants.EMAIL_OTP_EXPIRY_TIME);
        expiryTimeOTP.setDisplayName("Email OTP expiry time (Minutes)");
        expiryTimeOTP.setDescription("Please pick a value between 1 minute and 1440 minutes (1 day).");
        expiryTimeOTP.setDefaultValue(EmailOTPAuthenticatorConstants.OTP_EXPIRE_TIME_DEFAULT_IN_MINS);
        expiryTimeOTP.setDisplayOrder(3);
        configProperties.add(expiryTimeOTP);

        Property numericOTP = new Property();
        numericOTP.setName(EmailOTPAuthenticatorConstants.EMAIL_OTP_NUMERIC_OTP);
        numericOTP.setDisplayName("Use only numeric characters for OTP");
        numericOTP.setDescription("Please clear this checkbox to enable alphanumeric characters.");
        numericOTP.setDefaultValue("true");
        numericOTP.setType("boolean");
        numericOTP.setDisplayOrder(5);
        configProperties.add(numericOTP);

        return configProperties;
    }

    /**
     * Trigger event.
     *
     * @param user           Authenticated user.
     * @param otpCode        The OTP code returned for the authentication request.
     * @param sendToAddress  The email address to send the otp.
     * @param metaProperties Meta details.
     * @throws AuthenticationFailedException In occasions of failing to send the email to the user.
     */
    private void triggerEvent(AuthenticatedUser user, String otpCode, String sendToAddress,
                              Map<String, String> metaProperties) throws AuthenticationFailedException {

        String eventName = IdentityEventConstants.Event.TRIGGER_NOTIFICATION;
        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUserName());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
        properties.put(EmailOTPAuthenticatorConstants.CODE, otpCode);
        properties.put(EmailOTPAuthenticatorConstants.TEMPLATE_TYPE, EmailOTPAuthenticatorConstants.EVENT_NAME);
        properties.put(EmailOTPAuthenticatorConstants.ATTRIBUTE_EMAIL_SENT_TO, sendToAddress);

        if (metaProperties != null) {
            for (Map.Entry<String, String> metaProperty : metaProperties.entrySet()) {
                if (StringUtils.isNotBlank(metaProperty.getKey()) && StringUtils.isNotBlank(metaProperty.getValue())) {
                    properties.put(metaProperty.getKey(), metaProperty.getValue());
                }
            }
        }

        Event identityMgtEvent = new Event(eventName, properties);
        try {
            EmailOTPServiceDataHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            String errorMsg = "An error occurred while triggering the event. " + e.getMessage();
            throw new AuthenticationFailedException(errorMsg, e.getCause());
        }
    }

    /**
     * A method to get Expire Time configuration from EmailOTPUtils.
     *
     * @param context :  AuthenticationContext
     */
    private String getExpireTime(AuthenticationContext context) {

        String expireTime = EmailOTPUtils
                .getConfiguration(context, EmailOTPAuthenticatorConstants.TOKEN_EXPIRE_TIME_IN_MILIS);
        if (StringUtils.isEmpty(expireTime)) {
            expireTime = EmailOTPAuthenticatorConstants.OTP_EXPIRE_TIME_DEFAULT;
            if (log.isDebugEnabled()) {
                log.debug("OTP Expiration Time not specified default value will be used");
            }
        }
        return expireTime;
    }

    /**
     * A method to get disableOTPResendOnFailure configuration from EmailOTPUtils.
     *
     * @param context :  AuthenticationContext
     */
    private boolean isOTPResendingDisabledOnFailure(AuthenticationContext context) {

        String disableOTPResendOnFailure = EmailOTPUtils.getConfiguration(
                context, EmailOTPAuthenticatorConstants.DISABLE_OTP_RESEND_ON_FAILURE);
        if (StringUtils.isEmpty(disableOTPResendOnFailure)) {
            return false;
        }
        return Boolean.parseBoolean(disableOTPResendOnFailure);
    }

    /**
     * A method to get isOTPExpired configuration from EmailOTPUtils.
     *
     * @param context :  AuthenticationContext
     */
    private boolean isOTPExpired(AuthenticationContext context) {

        return Boolean.parseBoolean((String) context.getProperty(EmailOTPAuthenticatorConstants.OTP_EXPIRED));
    }

    /**
     * Checks whether otp is Expired or not.
     *
     * @param generatedTime : Email OTP generated time
     * @param context       : the Authentication Context
     */
    protected boolean isExpired(long generatedTime, AuthenticationContext context)
            throws AuthenticationFailedException {

        long expireTime;
        try {
            expireTime = Long.parseLong(getExpireTime(context));
        } catch (NumberFormatException e) {
            throw new AuthenticationFailedException("Invalid Email OTP expiration time configured.");
        }
        if (expireTime == -1) {
            if (log.isDebugEnabled()) {
                log.debug("Email OTP configured not to expire.");
            }
            return false;
        }
        return System.currentTimeMillis() >= generatedTime + expireTime;
    }

    /**
     * Get the user realm of the logged in user.
     *
     * @param username Username.
     * @return UserRealm.
     * @throws AuthenticationFailedException AuthenticatedFailedException.
     */
    private UserRealm getUserRealm(String username) throws AuthenticationFailedException {

        UserRealm userRealm = null;
        try {
            if (StringUtils.isNotEmpty(username)) {
                String tenantDomain = MultitenantUtils.getTenantDomain(username);
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                RealmService realmService = IdentityTenantUtil.getRealmService();
                userRealm = realmService.getTenantUserRealm(tenantId);
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Cannot find the user realm.", e);
        }
        return userRealm;
    }

    /**
     * Get the user realm of the logged in user.
     *
     * @param authenticatedUser Authenticated user.
     * @return UserRealm.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private UserRealm getUserRealm(AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        UserRealm userRealm = null;
        try {
            if (authenticatedUser != null) {
                String tenantDomain = authenticatedUser.getTenantDomain();
                int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
                RealmService realmService = IdentityTenantUtil.getRealmService();
                userRealm = realmService.getTenantUserRealm(tenantId);
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Cannot find the user realm.", e);
        }
        return userRealm;
    }

    /**
     * Reset OTP Failed Attempts count upon successful completion of the OTP verification.
     *
     * @param context Authentication context.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void resetOtpFailedAttempts(AuthenticationContext context) throws AuthenticationFailedException {

        /*
        Check whether account locking enabled for Email OTP to keep backward compatibility.
        Account locking is not done for federated flows.
         */
        if (!isLocalUser(context) || !EmailOTPUtils.isAccountLockingEnabledForEmailOtp(context)) {
            return;
        }
        AuthenticatedUser authenticatedUser = getAuthenticatedUser(context);
        Property[] connectorConfigs = EmailOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain());

        // Return if account lock handler is not enabled.
        for (Property connectorConfig : connectorConfigs) {
            if ((EmailOTPAuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE.equals(connectorConfig.getName())) &&
                    !Boolean.parseBoolean(connectorConfig.getValue())) {
                return;
            }
        }

        String usernameWithDomain =
                IdentityUtil.addDomainToName(authenticatedUser.getUserName(), authenticatedUser.getUserStoreDomain());
        try {
            UserRealm userRealm = getUserRealm(authenticatedUser);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();

            // Avoid updating the claims if they are already zero.
            String[] claimsToCheck = {EmailOTPAuthenticatorConstants.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM,
                    EmailOTPAuthenticatorConstants.ACCOUNT_LOCKED_CLAIM};
            Map<String, String> userClaims = userStoreManager.getUserClaimValues(usernameWithDomain, claimsToCheck,
                    UserCoreConstants.DEFAULT_PROFILE);
            String failedEmailOtpAttempts =
                    userClaims.get(EmailOTPAuthenticatorConstants.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM);
            String accountLockClaim =
                    userClaims.get(EmailOTPAuthenticatorConstants.ACCOUNT_LOCKED_CLAIM);

            if (NumberUtils.isNumber(failedEmailOtpAttempts) && Integer.parseInt(failedEmailOtpAttempts) > 0) {
                Map<String, String> updatedClaims = new HashMap<>();
                updatedClaims.put(EmailOTPAuthenticatorConstants.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM, "0");
                // Check the account lock claim to verify whether the user is previously locked.
                if (Boolean.parseBoolean(accountLockClaim)) {
                    // Update the account locking related claims upon successful completion of the OTP verification.
                    updatedClaims.put(EmailOTPAuthenticatorConstants.ACCOUNT_LOCKED_CLAIM, Boolean.FALSE.toString());
                    updatedClaims.put(EmailOTPAuthenticatorConstants.ACCOUNT_UNLOCK_TIME_CLAIM, "0");
                }
                userStoreManager
                        .setUserClaimValues(usernameWithDomain, updatedClaims, UserCoreConstants.DEFAULT_PROFILE);
            }
        } catch (UserStoreException e) {
            String errorMessage =
                    String.format("Failed to reset failed attempts count for user : %s.", authenticatedUser);
            log.error(errorMessage, e);
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    /**
     * Execute account lock flow for OTP verification failures.
     *
     * @param context Authentication context.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void handleOtpVerificationFail(AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(context);

        /*
        Account locking is not done for federated flows.
        Check whether account locking enabled for Email OTP to keep backward compatibility.
        No need to continue if the account is already locked.
         */
        if (!isLocalUser(context) || !EmailOTPUtils.isAccountLockingEnabledForEmailOtp(context) ||
                EmailOTPUtils.isAccountLocked(authenticatedUser)) {
            return;
        }

        int maxAttempts = 0;
        long unlockTimePropertyValue = 0;
        double unlockTimeRatio = 1;

        Property[] connectorConfigs = EmailOTPUtils.getAccountLockConnectorConfigs(authenticatedUser.getTenantDomain());
        for (Property connectorConfig : connectorConfigs) {
            switch (connectorConfig.getName()) {
                case EmailOTPAuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE:
                    if (!Boolean.parseBoolean(connectorConfig.getValue())) {
                        return;
                    }
                case EmailOTPAuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE_MAX:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        maxAttempts = Integer.parseInt(connectorConfig.getValue());
                    }
                    break;
                case EmailOTPAuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_TIME:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        unlockTimePropertyValue = Integer.parseInt(connectorConfig.getValue());
                    }
                    break;
                case EmailOTPAuthenticatorConstants.PROPERTY_LOGIN_FAIL_TIMEOUT_RATIO:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        double value = Double.parseDouble(connectorConfig.getValue());
                        if (value > 0) {
                            unlockTimeRatio = value;
                        }
                    }
                    break;
            }
        }

        Map<String, String> claimValues = getUserClaimValues(authenticatedUser, new String[]{
                EmailOTPAuthenticatorConstants.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM,
                EmailOTPAuthenticatorConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM});
        if (claimValues == null) {
            claimValues = new HashMap<>();
        }
        int currentAttempts = 0;
        if (NumberUtils.isNumber(claimValues.get(EmailOTPAuthenticatorConstants.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM))) {
            currentAttempts =
                    Integer.parseInt(claimValues.get(EmailOTPAuthenticatorConstants.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM));
        }
        int failedLoginLockoutCountValue = 0;
        if (NumberUtils.isNumber(claimValues.get(EmailOTPAuthenticatorConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM))) {
            failedLoginLockoutCountValue =
                    Integer.parseInt(claimValues.get(EmailOTPAuthenticatorConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM));
        }

        Map<String, String> updatedClaims = new HashMap<>();
        if ((currentAttempts + 1) >= maxAttempts) {
            // Calculate the incremental unlock-time-interval in milli seconds.
            unlockTimePropertyValue = (long) (unlockTimePropertyValue * 1000 * 60 * Math.pow(unlockTimeRatio,
                    failedLoginLockoutCountValue));
            // Calculate unlock-time by adding current-time and unlock-time-interval in milli seconds.
            long unlockTime = System.currentTimeMillis() + unlockTimePropertyValue;
            updatedClaims.put(EmailOTPAuthenticatorConstants.ACCOUNT_LOCKED_CLAIM, Boolean.TRUE.toString());
            updatedClaims.put(EmailOTPAuthenticatorConstants.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM, "0");
            updatedClaims.put(EmailOTPAuthenticatorConstants.ACCOUNT_UNLOCK_TIME_CLAIM, String.valueOf(unlockTime));
            updatedClaims.put(EmailOTPAuthenticatorConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM,
                    String.valueOf(failedLoginLockoutCountValue + 1));
            updatedClaims.put(EmailOTPAuthenticatorConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI,
                    EmailOTPAuthenticatorConstants.MAX_EMAIL_OTP_ATTEMPTS_EXCEEDED);
            IdentityUtil.threadLocalProperties.get().put(EmailOTPAuthenticatorConstants.ADMIN_INITIATED, false);
            setUserClaimValues(authenticatedUser, updatedClaims);
            throw new AuthenticationFailedException("User account is locked " + authenticatedUser.getUserName());
        } else {
            updatedClaims.put(EmailOTPAuthenticatorConstants.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM,
                    String.valueOf(currentAttempts + 1));
            setUserClaimValues(authenticatedUser, updatedClaims);
        }
    }

    /**
     * Check whether the user being authenticated via a local authenticator or not.
     *
     * @param context Authentication context.
     * @return Whether the user being authenticated via a local authenticator.
     */
    private boolean isLocalUser(AuthenticationContext context) {

        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        if (stepConfigMap != null) {
            for (StepConfig stepConfig : stepConfigMap.values()) {
                if (stepConfig.getAuthenticatedUser() != null && stepConfig.isSubjectAttributeStep()) {
                    if (LOCAL_AUTHENTICATOR.equals(stepConfig.getAuthenticatedIdP())) {
                        return true;
                    }
                    break;
                }
            }
        }
        return false;
    }

    private Map<String, String> getUserClaimValues(AuthenticatedUser authenticatedUser, String[] claims)
            throws AuthenticationFailedException {

        Map<String, String> claimValues;
        try {
            UserRealm userRealm = getUserRealm(authenticatedUser);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            claimValues = userStoreManager.getUserClaimValues(IdentityUtil.addDomainToName(
                    authenticatedUser.getUserName(), authenticatedUser.getUserStoreDomain()), claims,
                    UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            log.error("Error while reading user claims.", e);
            throw new AuthenticationFailedException(
                    String.format("Failed to read user claims for user : %s.", authenticatedUser), e);
        }
        return claimValues;
    }

    private void setUserClaimValues(AuthenticatedUser authenticatedUser, Map<String, String> updatedClaims)
            throws AuthenticationFailedException {

        try {
            UserRealm userRealm = getUserRealm(authenticatedUser);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            userStoreManager.setUserClaimValues(IdentityUtil.addDomainToName(authenticatedUser.getUserName(),
                    authenticatedUser.getUserStoreDomain()), updatedClaims, UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            log.error("Error while updating user claims", e);
            throw new AuthenticationFailedException(
                    String.format("Failed to update user claims for user : %s.", authenticatedUser), e);
        }
    }

    /**
     * Get user account unlock time in milli seconds. If no value configured for unlock time user claim, return 0.
     *
     * @param authenticatedUser The authenticated user.
     * @return User account unlock time in milli seconds. If no value is configured return 0.
     * @throws AuthenticationFailedException If an error occurred while getting the user unlock time.
     */
    private long getUnlockTimeInMilliSeconds(AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        Map<String, String> claimValues = getUserClaimValues(authenticatedUser,
                new String[]{EmailOTPAuthenticatorConstants.ACCOUNT_UNLOCK_TIME_CLAIM});
        if (claimValues.get(EmailOTPAuthenticatorConstants.ACCOUNT_UNLOCK_TIME_CLAIM) == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No value configured for claim: %s, of user: %s",
                        EmailOTPAuthenticatorConstants.ACCOUNT_UNLOCK_TIME_CLAIM, authenticatedUser.getUserName()));
            }
            return 0;
        }
        return Long.parseLong(claimValues.get(EmailOTPAuthenticatorConstants.ACCOUNT_UNLOCK_TIME_CLAIM));
    }

    private String getLockedReason(AuthenticatedUser authenticatedUser) throws AuthenticationFailedException {

        Map<String, String> claimValues = getUserClaimValues(authenticatedUser,
                new String[]{EmailOTPAuthenticatorConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI});
        return claimValues.get(EmailOTPAuthenticatorConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI);
    }

    /**
     * Trigger event after generating Email OTP.
     *
     * @param request HttpServletRequest.
     * @param context Authentication context.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void publishPostEmailOTPGeneratedEvent(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUser = (AuthenticatedUser) context.getProperty(EmailOTPAuthenticatorConstants
                .AUTHENTICATED_USER);
        if (authenticatedUser == null && isEmailOTPAsFirstFactor(context)) {
            return;
        }
        Map<String, String> emailOTPParameters = getAuthenticatorConfig().getParameterMap();
        String username = authenticatedUser.toFullQualifiedUsername();
        boolean isUserExist;
        try {
            isUserExist = FederatedAuthenticatorUtil.isUserExistInUserStore(username);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Failed to get the user from user store.", e);
        }
        if (isUserExist && isEmailOTPDisableForUser(username, context, emailOTPParameters)) {
            // Email OTP is disabled for the user. Hence not going to trigger the event.
            return;
        }
        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.CORRELATION_ID, context.getCallerSessionKey());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_NAME, authenticatedUser.getUserName());
        eventProperties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, context.getTenantDomain());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, authenticatedUser
                .getUserStoreDomain());
        eventProperties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, context.getServiceProviderName());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_AGENT, request.getHeader(
                EmailOTPAuthenticatorConstants.USER_AGENT));
        if (StringUtils.isNotEmpty(request.getParameter(EmailOTPAuthenticatorConstants.RESEND))) {
            if (log.isDebugEnabled()) {
                log.debug("Setting true resend-code property in event since http request has resendCode parameter.");
            }
            eventProperties.put(IdentityEventConstants.EventProperty.RESEND_CODE,
                    request.getParameter(EmailOTPAuthenticatorConstants.RESEND));
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Setting false resend-code property in event since http request has " +
                        "not resendCode parameter.");
            }
            eventProperties.put(IdentityEventConstants.EventProperty.RESEND_CODE, false);
        }

        eventProperties.put(IdentityEventConstants.EventProperty.GENERATED_OTP, context.getProperty(
                EmailOTPAuthenticatorConstants.OTP_TOKEN));
        Object otpGeneratedTimeProperty = context.getProperty(EmailOTPAuthenticatorConstants.OTP_GENERATED_TIME);
        if (otpGeneratedTimeProperty != null) {
            long otpGeneratedTime = (long) otpGeneratedTimeProperty;
            eventProperties.put(IdentityEventConstants.EventProperty.OTP_GENERATED_TIME, otpGeneratedTime);

            long expiryTime = otpGeneratedTime + Long.parseLong(getExpireTime(context));
            eventProperties.put(IdentityEventConstants.EventProperty.OTP_EXPIRY_TIME, expiryTime);
        }

        eventProperties.put(IdentityEventConstants.EventProperty.CLIENT_IP, IdentityUtil.getClientIpAddress(request));
        Event postOtpGenEvent = new Event(IdentityEventConstants.Event.POST_GENERATE_EMAIL_OTP, eventProperties);
        try {
            EmailOTPServiceDataHolder.getInstance().getIdentityEventService().handleEvent(postOtpGenEvent);
        } catch (IdentityEventException e) {
            String errorMsg = "An error occurred while triggering post event in Email OTP generation flow. "
                    + e.getMessage();
            throw new AuthenticationFailedException(errorMsg, e);
        }
    }

    /**
     * Trigger event after validating Email OTP.
     *
     * @param request HttpServletRequest.
     * @param context Authentication context.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void publishPostEmailOTPValidatedEvent(HttpServletRequest request,
                                                   AuthenticationContext context) throws AuthenticationFailedException {

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.CORRELATION_ID, context.getCallerSessionKey());
        AuthenticatedUser authenticatedUser = (AuthenticatedUser) context.getProperty(EmailOTPAuthenticatorConstants
                .AUTHENTICATED_USER);
        if (authenticatedUser == null && isEmailOTPAsFirstFactor(context)) {
            return;
        }

        eventProperties.put(IdentityEventConstants.EventProperty.USER_NAME, authenticatedUser.getUserName());
        eventProperties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, context.getTenantDomain());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, authenticatedUser
                .getUserStoreDomain());
        eventProperties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, context.getServiceProviderName());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_AGENT, request.getHeader(
                EmailOTPAuthenticatorConstants.USER_AGENT));
        eventProperties.put(IdentityEventConstants.EventProperty.CLIENT_IP, IdentityUtil.getClientIpAddress(request));
        eventProperties.put(IdentityEventConstants.EventProperty.GENERATED_OTP, context.getProperty(
                EmailOTPAuthenticatorConstants.OTP_TOKEN));
        eventProperties.put(IdentityEventConstants.EventProperty.USER_INPUT_OTP, request.getParameter(
                EmailOTPAuthenticatorConstants.CODE));
        eventProperties.put(IdentityEventConstants.EventProperty.OTP_USED_TIME, System.currentTimeMillis());

        long otpGeneratedTime = (long) context.getProperty(EmailOTPAuthenticatorConstants.OTP_GENERATED_TIME);
        eventProperties.put(IdentityEventConstants.EventProperty.OTP_GENERATED_TIME, otpGeneratedTime);

        long expiryTime = otpGeneratedTime + Long.parseLong(getExpireTime(context));
        eventProperties.put(IdentityEventConstants.EventProperty.OTP_EXPIRY_TIME, expiryTime);
        Object codeMismatch = context.getProperty(EmailOTPAuthenticatorConstants.CODE_MISMATCH);
        Object otpExpired = context.getProperty(EmailOTPAuthenticatorConstants.OTP_EXPIRED);

        String status;
        if (EmailOTPAuthenticatorConstants.TRUE.equals(otpExpired)) {
            status = EmailOTPAuthenticatorConstants.STATUS_OTP_EXPIRED;
        } else if (codeMismatch != null && (Boolean) codeMismatch) {
            status = EmailOTPAuthenticatorConstants.STATUS_CODE_MISMATCH;
        } else {
            status = EmailOTPAuthenticatorConstants.STATUS_SUCCESS;
            eventProperties.put(IdentityEventConstants.EventProperty.GENERATED_OTP, request.getParameter(
                    EmailOTPAuthenticatorConstants.CODE));
        }

        eventProperties.put(IdentityEventConstants.EventProperty.OTP_STATUS, status);
        Event postOtpValidateEvent = new Event(IdentityEventConstants.Event.POST_VALIDATE_EMAIL_OTP, eventProperties);
        try {
            EmailOTPServiceDataHolder.getInstance().getIdentityEventService().handleEvent(postOtpValidateEvent);
        } catch (IdentityEventException e) {
            String errorMsg = "An error occurred while triggering post event in Email OTP validation flow."
                    + e.getMessage();
            throw new AuthenticationFailedException(errorMsg, e);
        }
    }

    /**
     * Checks whether the email address update failure property has been set in the context and returns the boolean
     * value of it.
     *
     * @param context Authenticaton context
     * @return Returns whether the email address update has been failed
     */
    private boolean isEmailUpdateFailed(AuthenticationContext context) {

        return Boolean.parseBoolean(
                String.valueOf(context.getProperty(EmailOTPAuthenticatorConstants.EMAIL_UPDATE_FAILURE)));

    }

    /**
     * Check the value of the Code mismatched property in the context and returns the boolean value of it.
     *
     * @param context Authentication context
     * @return whether the OTP is mismatched status
     */
    private boolean isOTPMismatched(AuthenticationContext context) {

        return Boolean.parseBoolean(String.valueOf(
                context.getProperty(EmailOTPAuthenticatorConstants.CODE_MISMATCH)));
    }

    /**
     * This method is used to redirect the user to the username entering page (IDF: Identifier first).
     *
     * @param context  The authentication context.
     * @param response Response.
     * @throws AuthenticationFailedException AuthenticationFailedException.
     */
    private void redirectUserToIDF(HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        StringBuilder redirectUrl = new StringBuilder();
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        redirectUrl.append(loginPage);
        redirectUrl.append("?");

        String queryParams = context.getContextIdIncludedQueryParams();
        try {
            if (log.isDebugEnabled()) {
                String logMsg = String.format("Redirecting to identifier first flow since "
                        + "last authenticated user is null in SP: %s", context.getServiceProviderName());
                log.debug(logMsg);
            }
            redirectUrl.append(queryParams);
            redirectUrl.append("&");
            redirectUrl.append(EmailOTPAuthenticatorConstants.AUTHENTICATORS);
            redirectUrl.append(EmailOTPAuthenticatorConstants.IDF_HANDLER_NAME);
            redirectUrl.append(":");
            redirectUrl.append(EmailOTPAuthenticatorConstants.LOCAL_AUTHENTICATOR);
            response.sendRedirect(redirectUrl.toString());
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error while redirecting to the login page.", e);
        }
    }

    /**
     * This method is used to resolve the username from authentication request.
     *
     * @param request The httpServletRequest.
     * @throws AuthenticationFailedException In occasions of failing.
     */
    private String resolveUsernameFromRequest(HttpServletRequest request) throws AuthenticationFailedException {

        String identifierFromRequest = request.getParameter(EmailOTPAuthenticatorConstants.USER_NAME);
        if (StringUtils.isBlank(identifierFromRequest)) {
            throw new AuthenticationFailedException("Username cannot be null or empty");
        }
        return identifierFromRequest;
    }

    /**
     * This method is used to resolve the user from authentication request from identifier handler.
     *
     * @param request The httpServletRequest.
     * @param context The authentication context.
     * @throws AuthenticationFailedException In occasions of failing.
     */
    private AuthenticatedUser resolveUserFromRequest(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = resolveUsernameFromRequest(request);
        username = FrameworkUtils.preprocessUsername(username, context);
        AuthenticatedUser user = new AuthenticatedUser();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        String tenantDomain = MultitenantUtils.getTenantDomain(username);

        user.setAuthenticatedSubjectIdentifier(tenantAwareUsername);
        user.setUserName(tenantAwareUsername);
        user.setUserStoreDomain(userStoreDomain);
        user.setTenantDomain(tenantDomain);
        return user;
    }

    /**
     * This method is used to resolve an authenticated user from the user stores.
     *
     * @param authenticatedUser The authenticated user.
     * @return Authenticated user retrieved from the user store.
     * @throws AuthenticationFailedException In occasions of failing.
     */
    private AuthenticatedUser resolveUserFromUserStore(AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException {

        User user = getUser(authenticatedUser);
        if (user == null) {
            return null;
        }
        authenticatedUser = new AuthenticatedUser(user);
        authenticatedUser.setAuthenticatedSubjectIdentifier(user.getUsername());
        return authenticatedUser;
    }

    /**
     * This method is used to set the resolved user in context.
     *
     * @param context           The authentication context.
     * @param authenticatedUser The authenticated user.
     */
    private void setResolvedUserInContext(AuthenticationContext context, AuthenticatedUser authenticatedUser) {

        if (authenticatedUser != null) {
            String username = authenticatedUser.getUserName();
            authenticatedUser.setAuthenticatedSubjectIdentifier(username);
            context.setSubject(authenticatedUser);

            Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
            StepConfig currentStepConfig = stepConfigMap.get(context.getCurrentStep());
            currentStepConfig.setAuthenticatedUser(authenticatedUser);
            currentStepConfig.setAuthenticatedIdP(LOCAL_AUTHENTICATOR);
        }
    }

    /**
     * Generate the OTP according to the configuration parameters.
     *
     * @param context AuthenticationContext.
     * @return Generated OTP.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private String generateOTP(AuthenticationContext context) throws AuthenticationFailedException {

        String charSet = getOTPCharset(context);
        int otpLength = (int) context.getProperty(EmailOTPAuthenticatorConstants.EMAIL_OTP_LENGTH);

        char[] chars = charSet.toCharArray();
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < otpLength; i++) {
            stringBuilder.append(chars[secureRandom.nextInt(chars.length)]);
        }
        return stringBuilder.toString();
    }

    private String getOTPCharset(AuthenticationContext context) {

        boolean useOnlyNumericChars = !Boolean.parseBoolean
                (String.valueOf(context.getProperty(EmailOTPAuthenticatorConstants.IS_CHAR_IN_OTP)));
        if (useOnlyNumericChars) {
            return EmailOTPAuthenticatorConstants.EMAIL_OTP_NUMERIC_CHAR_SET;
        }
        return EmailOTPAuthenticatorConstants.EMAIL_OTP_UPPER_CASE_ALPHABET_CHAR_SET
                + EmailOTPAuthenticatorConstants.EMAIL_OTP_NUMERIC_CHAR_SET;
    }

    /**
     * Append the recaptcha related params if recaptcha is enabled for Email OTP.
     *
     * @param request       HttpServletRequest.
     * @return String with the appended recaptcha params.
     */
    private String getCaptchaParams(HttpServletRequest request, AuthenticationContext context) {

        String captchaParams = "";
        EmailOTPCaptchaConnector emailOTPCaptchaConnector = new EmailOTPCaptchaConnector();
        emailOTPCaptchaConnector.init(EmailOTPServiceDataHolder.getInstance().getIdentityGovernanceService());
        try {
            if (emailOTPCaptchaConnector.isEmailRecaptchaEnabled(request) && isEmailOTPAsFirstFactor(context)) {
                captchaParams = "&reCaptcha=true";
            }
        } catch (CaptchaException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to determine if recaptcha for Email OTP is enabled", e);
            }
        }
        return captchaParams;
    }

    /**
     * This method checks if all the authentication steps up to now have been performed by authenticators that
     * implements AuthenticationFlowHandler interface. If so, it returns true.
     * AuthenticationFlowHandlers may not perform actual authentication though the authenticated user is set in the
     * context. Hence, this method can be used to determine if the user has been authenticated by a previous step.
     *
     * @param context   AuthenticationContext.
     * @return True if all the authentication steps up to now have been performed by AuthenticationFlowHandlers.
     */
    private boolean isPreviousIdPAuthenticationFlowHandler(AuthenticationContext context) {

        Map<String, AuthenticatedIdPData> currentAuthenticatedIdPs = context.getCurrentAuthenticatedIdPs();
        return currentAuthenticatedIdPs != null && !currentAuthenticatedIdPs.isEmpty() &&
                currentAuthenticatedIdPs.values().stream().filter(Objects::nonNull)
                        .map(AuthenticatedIdPData::getAuthenticators).filter(Objects::nonNull)
                        .flatMap(List::stream)
                        .allMatch(authenticator ->
                                authenticator.getApplicationAuthenticator() instanceof AuthenticationFlowHandler);
    }

    private boolean isEmailOTPAsFirstFactor(AuthenticationContext context) {

        return (context.getCurrentStep() == 1 || isPreviousIdPAuthenticationFlowHandler(context));
    }
}
