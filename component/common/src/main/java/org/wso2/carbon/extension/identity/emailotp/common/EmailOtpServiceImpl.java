/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.com).
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.extension.identity.emailotp.common;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.extension.identity.emailotp.common.constant.Constants;
import org.wso2.carbon.extension.identity.emailotp.common.dto.FailureReasonDTO;
import org.wso2.carbon.extension.identity.emailotp.common.dto.GenerationResponseDTO;
import org.wso2.carbon.extension.identity.emailotp.common.dto.SessionDTO;
import org.wso2.carbon.extension.identity.emailotp.common.dto.ValidationResponseDTO;
import org.wso2.carbon.extension.identity.emailotp.common.exception.EmailOtpException;
import org.wso2.carbon.extension.identity.emailotp.common.exception.EmailOtpServerException;
import org.wso2.carbon.extension.identity.emailotp.common.internal.EmailOtpServiceDataHolder;
import org.wso2.carbon.extension.identity.emailotp.common.util.OneTimePasswordUtils;
import org.wso2.carbon.extension.identity.emailotp.common.util.Utils;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannels;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.identity.recovery.internal.IdentityRecoveryServiceDataHolder;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.constants.UserCoreErrorConstants;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * This class implements the EmailOtpService interface.
 */
public class EmailOtpServiceImpl implements EmailOtpService {

    private static final Log log = LogFactory.getLog(EmailOtpServiceImpl.class);

    @Override
    public GenerationResponseDTO generateEmailOTP(String userId) throws EmailOtpException {

        if (StringUtils.isBlank(userId)) {
            throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_EMPTY_USER_ID, null);
        }

        // Retrieve email only if notifications the are managed internally.
        boolean sendNotification = EmailOtpServiceDataHolder.getConfigs().isTriggerNotification();
        String[] requestedClaims =
                sendNotification ? new String[]{NotificationChannels.EMAIL_CHANNEL.getClaimUri()} : null;

        // Retrieve user by ID.
        AbstractUserStoreManager userStoreManager;
        User user;
        try {
            userStoreManager = (AbstractUserStoreManager) EmailOtpServiceDataHolder.getInstance()
                    .getRealmService().getTenantUserRealm(getTenantId()).getUserStoreManager();
            user = userStoreManager.getUserWithID(userId, requestedClaims, UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            // Handle user not found.
            String errorCode = ((org.wso2.carbon.user.core.UserStoreException) e).getErrorCode();
            if (UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER.getCode().equals(errorCode)) {
                throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_INVALID_USER_ID, userId);
            }
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR,
                    String.format("Error while retrieving user for the Id : %s.", userId), e);
        }

        // If throttling is enabled, check if the resend request has sent too early.
        boolean resendThrottlingEnabled = EmailOtpServiceDataHolder.getConfigs().isResendThrottlingEnabled();
        if (resendThrottlingEnabled) {
            shouldThrottle(userId);
        }

        String emailAddress = sendNotification ? getEmailAddress(user) : null;
        if (sendNotification && StringUtils.isBlank(emailAddress)) {
            throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_BLANK_EMAIL_ADDRESS, user.getUserID());
        }

        int emailOtpExpiryTime = EmailOtpServiceDataHolder.getConfigs().getOtpValidityPeriod();
        SessionDTO sessionDTO = issueOTP(user, emailOtpExpiryTime);

        GenerationResponseDTO responseDTO = new GenerationResponseDTO();
        // If WSO2IS is handling the notifications, don't send the OTP in the response.
        if (!sendNotification) {
            responseDTO.setEmailOTP(sessionDTO.getOtpToken());
        }
        responseDTO.setTransactionId(sessionDTO.getTransactionId());
        return responseDTO;
    }

    @Override
    public GenerationResponseDTO generateEmailOTP(String userId, String emailOtpExpiryTime) throws EmailOtpException {

        if (StringUtils.isBlank(userId)) {
            throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_EMPTY_USER_ID, null);
        }

            // Retrieve email only if notifications the are managed internally.
            boolean sendNotification = EmailOtpServiceDataHolder.getConfigs().isTriggerNotification();
            String[] requestedClaims =
                    sendNotification ? new String[]{NotificationChannels.EMAIL_CHANNEL.getClaimUri()} : null;

            // Retrieve user by ID.
            AbstractUserStoreManager userStoreManager;
            User user;
            try {
                userStoreManager = (AbstractUserStoreManager) EmailOtpServiceDataHolder.getInstance()
                        .getRealmService().getTenantUserRealm(getTenantId()).getUserStoreManager();
                user = userStoreManager.getUserWithID(userId, requestedClaims, UserCoreConstants.DEFAULT_PROFILE);
            } catch (UserStoreException e) {
                // Handle user not found.
                String errorCode = ((org.wso2.carbon.user.core.UserStoreException) e).getErrorCode();
                if (UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER.getCode().equals(errorCode)) {
                    throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_INVALID_USER_ID, userId);
                }
                throw Utils.handleServerException(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR,
                        String.format("Error while retrieving user for the Id : %s.", userId), e);
            }

            // If throttling is enabled, check if the resend request has sent too early.
            boolean resendThrottlingEnabled = EmailOtpServiceDataHolder.getConfigs().isResendThrottlingEnabled();
            if (resendThrottlingEnabled) {
                shouldThrottle(userId);
            }

            String emailAddress = sendNotification ? getEmailAddress(user) : null;
            if (sendNotification && StringUtils.isBlank(emailAddress)) {
                throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_BLANK_EMAIL_ADDRESS, user.getUserID());
            }

            SessionDTO sessionDTO = issueOTP(user, Integer.parseInt(emailOtpExpiryTime));

            GenerationResponseDTO responseDTO = new GenerationResponseDTO();
            // If WSO2IS is handling the notifications, don't send the OTP in the response.
            if (!sendNotification) {
                responseDTO.setEmailOTP(sessionDTO.getOtpToken());
            }
            responseDTO.setTransactionId(sessionDTO.getTransactionId());
            responseDTO.setEmailOtpExpiryTime(emailOtpExpiryTime);
            return responseDTO;

    }

    @Override
    public ValidationResponseDTO validateEmailOTP(String transactionId, String userId, String emailOTP)
            throws EmailOtpException {

        // Sanitize inputs.
        if (StringUtils.isBlank(transactionId) || StringUtils.isBlank(userId) || StringUtils.isBlank(emailOTP)) {
            String missingParam = StringUtils.isBlank(transactionId) ? "transactionId"
                    : StringUtils.isBlank(userId) ? "userId"
                    : "emailOTP";
            throw Utils.handleClientException(
                    Constants.ErrorMessage.CLIENT_MANDATORY_VALIDATION_PARAMETERS_EMPTY, missingParam);
        }

        boolean showFailureReason = EmailOtpServiceDataHolder.getConfigs().isShowFailureReason();
        boolean isEnableMultipleSessions = EmailOtpServiceDataHolder.getConfigs().isEnableMultipleSessions();

        // Retrieve session from the database.

        if(!isEnableMultipleSessions) {
            String sessionId = Utils.getHash(userId);
            String jsonString = (String) SessionDataStore.getInstance()
                    .getSessionData(sessionId, Constants.SESSION_TYPE_OTP);
            if (StringUtils.isBlank(jsonString)) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("No OTP session found for the user : %s.", userId));
                }
                FailureReasonDTO error = showFailureReason
                        ? new FailureReasonDTO(Constants.ErrorMessage.CLIENT_NO_OTP_FOR_USER, userId)
                        : null;
                return new ValidationResponseDTO(userId, false, error);
            }
            SessionDTO sessionDTO;
            try {
                sessionDTO = new ObjectMapper().readValue(jsonString, SessionDTO.class);
            } catch (IOException e) {
                throw Utils.handleServerException(Constants.ErrorMessage.SERVER_JSON_SESSION_MAPPER_ERROR, null, e);
            }

            ValidationResponseDTO responseDTO = isValid(sessionDTO, emailOTP, userId, transactionId, showFailureReason,
                    true);
            if (!responseDTO.isValid()) {
                return responseDTO;
            }
            // Valid OTP. Clear OTP session data.
                SessionDataStore.getInstance().clearSessionData(Utils.getHash(userId), Constants.SESSION_TYPE_OTP);

            resetOtpFailedAttempts(userId);

            return new ValidationResponseDTO(userId, true);
        } else {
            String sessionId = Utils.getHash(userId, transactionId);
            String jsonString = (String) SessionDataStore.getInstance()
                    .getSessionData(sessionId, Constants.SESSION_TYPE_OTP);
            if (StringUtils.isBlank(jsonString)) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("No OTP session found for the user : %s.", userId));
                }
                FailureReasonDTO error = showFailureReason
                        ? new FailureReasonDTO(Constants.ErrorMessage.CLIENT_NO_OTP_FOR_USER, userId)
                        : null;
                return new ValidationResponseDTO(userId, false, error);
            }
            SessionDTO sessionDTO;
            try {
                sessionDTO = new ObjectMapper().readValue(jsonString, SessionDTO.class);
            } catch (IOException e) {
                throw Utils.handleServerException(Constants.ErrorMessage.SERVER_JSON_SESSION_MAPPER_ERROR, null, e);
            }

            ValidationResponseDTO responseDTO = isValid(sessionDTO, emailOTP, userId, transactionId, showFailureReason,
                    true);
            if (!responseDTO.isValid()) {
                return responseDTO;
            }

            // Valid OTP. Clear OTP session data.
            SessionDataStore.getInstance().clearSessionData(Utils.getHash(userId, transactionId), Constants.SESSION_TYPE_OTP);

            resetOtpFailedAttempts(userId);

            return new ValidationResponseDTO(userId, true);
        }
    }

    @Override
    public ValidationResponseDTO verifyEmailOTP(String transactionId, String userId, String emailOTP) throws EmailOtpException {

        boolean isEnableMultipleSessions = EmailOtpServiceDataHolder.getConfigs().isEnableMultipleSessions();
        boolean showFailureReason = EmailOtpServiceDataHolder.getConfigs().isShowFailureReason();

        // Sanitize inputs.
        if (StringUtils.isBlank(transactionId) || StringUtils.isBlank(userId) || StringUtils.isBlank(emailOTP)) {
            String missingParam = StringUtils.isBlank(transactionId) ? "transactionId"
                    : StringUtils.isBlank(userId) ? "userId"
                    : "emailOTP";
            throw Utils.handleClientException(
                    Constants.ErrorMessage.CLIENT_MANDATORY_VALIDATION_PARAMETERS_EMPTY, missingParam);
        }

        // Retrieve session from the database.
        if(!isEnableMultipleSessions) {
            String sessionId = Utils.getHash(userId);
            String jsonString = (String) SessionDataStore.getInstance()
                    .getSessionData(sessionId, Constants.SESSION_TYPE_OTP);
            if (StringUtils.isBlank(jsonString)) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("No OTP session found for the user : %s.", userId));
                }
                FailureReasonDTO error = showFailureReason
                        ? new FailureReasonDTO(Constants.ErrorMessage.CLIENT_NO_OTP_FOR_USER, userId)
                        : null;
                return new ValidationResponseDTO(userId, false, error);
            }
            SessionDTO sessionDTO;
            try {
                sessionDTO = new ObjectMapper().readValue(jsonString, SessionDTO.class);
            } catch (IOException e) {
                throw Utils.handleServerException(Constants.ErrorMessage.SERVER_JSON_SESSION_MAPPER_ERROR, null, e);
            }

            ValidationResponseDTO responseDTO = isValid(sessionDTO, emailOTP, userId, transactionId, showFailureReason,
                    false);
            if (!responseDTO.isValid()) {
                return responseDTO;
            }

            return new ValidationResponseDTO(userId, true);
        } else {
            String sessionId = Utils.getHash(userId, transactionId);
            String jsonString = (String) SessionDataStore.getInstance()
                    .getSessionData(sessionId, Constants.SESSION_TYPE_OTP);
            if (StringUtils.isBlank(jsonString)) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("No OTP session found for the user : %s.", userId));
                }
                FailureReasonDTO error = showFailureReason
                        ? new FailureReasonDTO(Constants.ErrorMessage.CLIENT_NO_OTP_FOR_USER, userId)
                        : null;
                return new ValidationResponseDTO(userId, false, error);
            }
            SessionDTO sessionDTO;
            try {
                sessionDTO = new ObjectMapper().readValue(jsonString, SessionDTO.class);
            } catch (IOException e) {
                throw Utils.handleServerException(Constants.ErrorMessage.SERVER_JSON_SESSION_MAPPER_ERROR, null, e);
            }

            ValidationResponseDTO responseDTO = isValid(sessionDTO, emailOTP, userId, transactionId, showFailureReason,
                    false);
            if (!responseDTO.isValid()) {
                return responseDTO;
            }

            return new ValidationResponseDTO(userId, true);
        }
    }

    private ValidationResponseDTO isValid(SessionDTO sessionDTO, String emailOtp, String userId, String transactionId,
                                          boolean showFailureReason, boolean checkAccountLock)
            throws EmailOtpException {

        FailureReasonDTO error;
        // Check if the provided OTP is correct.
        if (!StringUtils.equals(emailOtp, sessionDTO.getOtpToken())) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Invalid OTP provided for the user : %s.", userId));
            }
            if (checkAccountLock) {
                ValidationResponseDTO responseDTO = handleAccountLock(userId, showFailureReason);
                if (responseDTO != null) {
                    return responseDTO;
                }
            }
            error = showFailureReason
                    ? new FailureReasonDTO(Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED, userId)
                    : null;
            return new ValidationResponseDTO(userId, false, error);
        }

        // Check for expired OTPs.
        if (System.currentTimeMillis() > sessionDTO.getExpiryTime()) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Expired OTP provided for the user : %s.", userId));
            }
            error = showFailureReason ? new FailureReasonDTO(Constants.ErrorMessage.CLIENT_EXPIRED_OTP, userId) : null;
            return new ValidationResponseDTO(userId, false, error);
        }
        // Check if the provided transaction ID is correct.
        if (!StringUtils.equals(transactionId, sessionDTO.getTransactionId())) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Provided transaction Id doesn't match. User : %s.", userId));
            }
            error = showFailureReason ?
                    new FailureReasonDTO(Constants.ErrorMessage.CLIENT_INVALID_TRANSACTION_ID, transactionId) : null;
            return new ValidationResponseDTO(userId, false, error);
        }
        return new ValidationResponseDTO(userId, true);
    }

    private SessionDTO issueOTP(User user, int emailOtpExpiryTime) throws EmailOtpException {

        boolean triggerNotification = EmailOtpServiceDataHolder.getConfigs().isTriggerNotification();
        boolean resendSameOtp = EmailOtpServiceDataHolder.getConfigs().isResendSameOtp();
        boolean isEnableMultipleSessions = EmailOtpServiceDataHolder.getConfigs().isEnableMultipleSessions();

        // If 'Resend same OTP' is enabled, check if such OTP exists.
        SessionDTO sessionDTO = null;
        if (resendSameOtp && !isEnableMultipleSessions) {
            sessionDTO = getPreviousValidOTPSession(user);
            // This is done in order to support 'resend throttling'.
            if (sessionDTO != null) {
                String transactionId = sessionDTO.getTransactionId();
                String sessionId = Utils.getHash(user.getUserID());
                // Remove previous OTP session.
                SessionDataStore.getInstance().clearSessionData(sessionId, Constants.SESSION_TYPE_OTP);
                // Re-persisting after changing the 'generated time' of the OTP session.
                sessionDTO.setGeneratedTime(System.currentTimeMillis());
                persistOTPSession(sessionDTO, sessionId);
            }
        }

        // If no such valid OTPs exist, generate a new OTP and proceed.
        if (sessionDTO == null) {
            sessionDTO = generateNewOTP(user, emailOtpExpiryTime);
        }

        // Sending Email notifications.
        if (triggerNotification) {
            triggerNotification(user, sessionDTO.getOtpToken());
        }
        return sessionDTO;
    }

    private SessionDTO generateNewOTP(User user, int emailOtpExpiryTime) throws EmailOtpServerException {

        boolean isAlphaNumericOtpEnabled = EmailOtpServiceDataHolder.getConfigs().isAlphaNumericOTP();
        int otpLength = EmailOtpServiceDataHolder.getConfigs().getOtpLength();
        boolean isEnableMultipleSessions = EmailOtpServiceDataHolder.getConfigs().isEnableMultipleSessions();

        // Generate OTP.
        String transactionId = Utils.createTransactionId();
        String otp = OneTimePasswordUtils.generateOTP(transactionId, String.valueOf(Constants.NUMBER_BASE), otpLength,
                isAlphaNumericOtpEnabled);

        // Save the otp in the 'IDN_AUTH_SESSION_STORE' table.
        SessionDTO sessionDTO = new SessionDTO();
        sessionDTO.setOtpToken(otp);
        sessionDTO.setGeneratedTime(System.currentTimeMillis());
        sessionDTO.setExpiryTime(sessionDTO.getGeneratedTime() + emailOtpExpiryTime);
        sessionDTO.setTransactionId(transactionId);
        sessionDTO.setFullQualifiedUserName(user.getFullQualifiedUsername());
        sessionDTO.setUserId(user.getUserID());

        if(!isEnableMultipleSessions== true) {
            String sessionId = Utils.getHash(user.getUserID());
            persistOTPSession(sessionDTO, sessionId);
        } else {
            String sessionId = Utils.getHash(user.getUserID(), transactionId);
            persistOTPSession(sessionDTO, sessionId);
        }
        return sessionDTO;
    }

    private void triggerNotification(User user, String otp) throws EmailOtpException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Sending Email OTP notification to user Id: %s.", user.getUserID()));
        }

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUsername());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
        properties.put(IdentityEventConstants.EventProperty.NOTIFICATION_CHANNEL,
                NotificationChannels.EMAIL_CHANNEL.getChannelType());
        properties.put(IdentityRecoveryConstants.TEMPLATE_TYPE, Constants.NOTIFICATION_TYPE_EMAIL_OTP);
        properties.put(IdentityRecoveryConstants.SEND_TO, getEmailAddress(user));
        properties.put(Constants.OTP_CODE, otp);

        Event event = new Event(IdentityEventConstants.Event.TRIGGER_NOTIFICATION, properties);
        try {
            IdentityRecoveryServiceDataHolder.getInstance().getIdentityEventService().handleEvent(event);
        } catch (IdentityEventException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_NOTIFICATION_SENDING_ERROR,
                    user.getFullQualifiedUsername(), e);
        }
    }

    private String getEmailAddress(User user) {

        Map<String, String> userAttributes = user.getAttributes();
        return userAttributes.get(NotificationChannels.EMAIL_CHANNEL.getClaimUri());
    }

    private SessionDTO getPreviousValidOTPSession(User user) throws EmailOtpException {

        // Search previous session object.
        String sessionId = Utils.getHash(user.getUserID());
        String jsonString = (String) SessionDataStore.getInstance().
                getSessionData(sessionId, Constants.SESSION_TYPE_OTP);
        if (StringUtils.isBlank(jsonString)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No valid sessions found for the user Id: %s.", user.getUserID()));
            }
            return null;
        }
        SessionDTO previousOTPSessionDTO;
        try {
            previousOTPSessionDTO = new ObjectMapper().readValue(jsonString, SessionDTO.class);
        } catch (IOException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_JSON_SESSION_MAPPER_ERROR, null, e);
        }
        // If the previous OTP is issued within the interval, return the same.
        int otpRenewalInterval = EmailOtpServiceDataHolder.getConfigs().getOtpRenewalInterval();
        long elapsedTime = System.currentTimeMillis() - previousOTPSessionDTO.getGeneratedTime();
        boolean isValidToResend = elapsedTime < otpRenewalInterval;
        if (isValidToResend) {
            return previousOTPSessionDTO;
        }
        return null;
    }

    private void persistOTPSession(SessionDTO sessionDTO, String sessionId) throws EmailOtpServerException {

        String jsonString;
        try {
            jsonString = new ObjectMapper().writeValueAsString(sessionDTO);
        } catch (JsonProcessingException e) {
            throw Utils.handleServerException(
                    Constants.ErrorMessage.SERVER_SESSION_JSON_MAPPER_ERROR, e.getMessage(), e);
        }
        SessionDataStore.getInstance().storeSessionData(sessionId, Constants.SESSION_TYPE_OTP, jsonString,
                getTenantId());
        if (log.isDebugEnabled()) {
            log.debug(String.format("Successfully persisted the OTP for the user Id: %s.", sessionDTO.getUserId()));
        }
    }

    private void shouldThrottle(String userId) throws EmailOtpException {

        boolean isEnableMultipleSessions = EmailOtpServiceDataHolder.getConfigs().isEnableMultipleSessions();

        SessionDTO sessionDTO = null;
        if (!isEnableMultipleSessions) {
            String sessionId = Utils.getHash(userId);
            String jsonString = (String) SessionDataStore.getInstance().
                    getSessionData(sessionId, Constants.SESSION_TYPE_OTP);
            if (StringUtils.isBlank(jsonString)) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("No OTP session found for the user : %s.", userId));
                }
                return;
            }

            SessionDTO previousOTPSessionDTO;
            try {
                previousOTPSessionDTO = new ObjectMapper().readValue(jsonString, SessionDTO.class);
            } catch (IOException e) {
                throw Utils.handleServerException(Constants.ErrorMessage.SERVER_JSON_SESSION_MAPPER_ERROR, null, e);
            }

            long elapsedTimeSinceLastOtp = System.currentTimeMillis() - previousOTPSessionDTO.getGeneratedTime();
            int resendThrottleInterval = EmailOtpServiceDataHolder.getConfigs().getResendThrottleInterval();
            if (elapsedTimeSinceLastOtp < resendThrottleInterval) {
                long waitingPeriod = (resendThrottleInterval - elapsedTimeSinceLastOtp) / 1000;
                throw Utils.handleClientException(
                        Constants.ErrorMessage.CLIENT_SLOW_DOWN_RESEND, String.valueOf(waitingPeriod));
            }
        } else {
            String sessionId = Utils.getHash(userId, sessionDTO.getTransactionId());
            String jsonString = (String) SessionDataStore.getInstance().
                    getSessionData(sessionId, Constants.SESSION_TYPE_OTP);
            if (StringUtils.isBlank(jsonString)) {
                if(log.isDebugEnabled()){
                    log.debug(String.format("No OTP session found for the user : %s.", userId));
                }
                return;
            }

            SessionDTO previousOTPSessionDTO;
            try {
                previousOTPSessionDTO = new ObjectMapper().readValue(jsonString, SessionDTO.class);
            } catch (IOException e) {
                throw Utils.handleServerException(Constants.ErrorMessage.SERVER_JSON_SESSION_MAPPER_ERROR, null, e);
            }

            long elapsedTimeSinceLastOtp = System.currentTimeMillis() - previousOTPSessionDTO.getGeneratedTime();
            int resendThrottleInterval = EmailOtpServiceDataHolder.getConfigs().getResendThrottleInterval();
            if (elapsedTimeSinceLastOtp < resendThrottleInterval) {
                long waitingPeriod = (resendThrottleInterval - elapsedTimeSinceLastOtp) / 1000;
                throw Utils.handleClientException(
                        Constants.ErrorMessage.CLIENT_SLOW_DOWN_RESEND, String.valueOf(waitingPeriod));
            }
        }
    }

    private int getTenantId() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
    }

    /**
     * Reset OTP Failed Attempts count upon successful completion of the OTP verification.
     *
     * @param userId The ID of the user.
     * @throws EmailOtpException If an error occurred.
     */
    private void resetOtpFailedAttempts(String userId) throws EmailOtpException {

        if (!EmailOtpServiceDataHolder.getConfigs().isLockAccountOnFailedAttempts()) {
            return;
        }

        User user = getUserById(userId);
        Property[] connectorConfigs = Utils.getAccountLockConnectorConfigs(user.getTenantDomain());
        // Return if account lock handler is not enabled.
        for (Property connectorConfig : connectorConfigs) {
            if ((Constants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE.equals(connectorConfig.getName())) &&
                    !Boolean.parseBoolean(connectorConfig.getValue())) {
                return;
            }
        }

        try {
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) EmailOtpServiceDataHolder
                    .getInstance().getRealmService().getTenantUserRealm(getTenantId()).getUserStoreManager();

            String[] claimsToCheck = {Constants.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM, Constants.ACCOUNT_LOCKED_CLAIM};
            Map<String, String> userClaims = userStoreManager.getUserClaimValues(user.getDomainQualifiedUsername(),
                    claimsToCheck, UserCoreConstants.DEFAULT_PROFILE);
            String failedEmailOtpAttemptsClaimValue = userClaims.get(Constants.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM);
            String accountLockClaimValue = userClaims.get(Constants.ACCOUNT_LOCKED_CLAIM);

            Map<String, String> updatedClaims = new HashMap<>();
            if (NumberUtils.isNumber(failedEmailOtpAttemptsClaimValue) &&
                    Integer.parseInt(failedEmailOtpAttemptsClaimValue) > 0) {
                updatedClaims.put(Constants.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM, "0");
            }
            if (Boolean.parseBoolean(accountLockClaimValue)) {
                updatedClaims.put(Constants.ACCOUNT_LOCKED_CLAIM, Boolean.FALSE.toString());
                updatedClaims.put(Constants.ACCOUNT_UNLOCK_TIME_CLAIM, "0");
            }
            if (!updatedClaims.isEmpty()) {
                userStoreManager.setUserClaimValues(user.getDomainQualifiedUsername(), updatedClaims,
                        UserCoreConstants.DEFAULT_PROFILE);
            }
        } catch (UserStoreException e) {
            String errorMessage = String.format("Failed to reset failed attempts count for user ID : %s.",
                    user.getUserID());
            log.error(errorMessage, e);
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR,
                    errorMessage, e);
        }
    }

    private ValidationResponseDTO handleAccountLock(String userId, boolean showFailureReason) throws
            EmailOtpException {

        boolean lockAccountOnFailedAttempts = EmailOtpServiceDataHolder.getConfigs().isLockAccountOnFailedAttempts();
        if (!lockAccountOnFailedAttempts) {
            return null;
        }

        User user = getUserById(userId);
        if (Utils.isAccountLocked(user)) {
            FailureReasonDTO error = showFailureReason
                    ? new FailureReasonDTO(Constants.ErrorMessage.CLIENT_ACCOUNT_LOCKED, userId)
                    : null;
            return new ValidationResponseDTO(userId, false, error);
        }

        int maxAttempts = 0;
        long unlockTimePropertyValue = 0;
        double unlockTimeRatio = 1;

        Property[] connectorConfigs = Utils.getAccountLockConnectorConfigs(user.getTenantDomain());
        for (Property connectorConfig : connectorConfigs) {
            switch (connectorConfig.getName()) {
                case Constants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE:
                    if (!Boolean.parseBoolean(connectorConfig.getValue())) {
                        return null;
                    }
                case Constants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE_MAX:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        maxAttempts = Integer.parseInt(connectorConfig.getValue());
                    }
                    break;
                case Constants.PROPERTY_ACCOUNT_LOCK_TIME:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        unlockTimePropertyValue = Integer.parseInt(connectorConfig.getValue());
                    }
                    break;
                case Constants.PROPERTY_LOGIN_FAIL_TIMEOUT_RATIO:
                    if (NumberUtils.isNumber(connectorConfig.getValue())) {
                        double value = Double.parseDouble(connectorConfig.getValue());
                        if (value > 0) {
                            unlockTimeRatio = value;
                        }
                    }
                    break;
            }
        }

        Map<String, String> claimValues = getUserClaimValues(user, new String[]{
                Constants.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM, Constants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM});
        if (claimValues == null) {
            claimValues = new HashMap<>();
        }
        int currentAttempts = 0;
        if (NumberUtils.isNumber(claimValues.get(Constants.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM))) {
            currentAttempts = Integer.parseInt(claimValues.get(Constants.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM));
        }
        int failedLoginLockoutCountValue = 0;
        if (NumberUtils.isNumber(claimValues.get(Constants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM))) {
            failedLoginLockoutCountValue = Integer.parseInt(claimValues.get(Constants
                    .FAILED_LOGIN_LOCKOUT_COUNT_CLAIM));
        }

        Map<String, String> updatedClaims = new HashMap<>();
        if ((currentAttempts + 1) >= maxAttempts) {
            // Calculate the incremental unlock time interval in milli seconds.
            unlockTimePropertyValue = (long) (unlockTimePropertyValue * 1000 * 60 * Math.pow(unlockTimeRatio,
                    failedLoginLockoutCountValue));
            // Calculate unlock time by adding current time and unlock time interval in milliseconds.
            long unlockTime = System.currentTimeMillis() + unlockTimePropertyValue;
            updatedClaims.put(Constants.ACCOUNT_LOCKED_CLAIM, Boolean.TRUE.toString());
            updatedClaims.put(Constants.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM, "0");
            updatedClaims.put(Constants.ACCOUNT_UNLOCK_TIME_CLAIM, String.valueOf(unlockTime));
            updatedClaims.put(Constants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM,
                    String.valueOf(failedLoginLockoutCountValue + 1));
            updatedClaims.put(Constants.ACCOUNT_LOCKED_REASON_CLAIM_URI, Constants.MAX_EMAIL_OTP_ATTEMPTS_EXCEEDED);
            IdentityUtil.threadLocalProperties.get().put(Constants.ADMIN_INITIATED, false);
            setUserClaimValues(user, updatedClaims);
            FailureReasonDTO error = showFailureReason
                    ? new FailureReasonDTO(Constants.ErrorMessage.CLIENT_ACCOUNT_LOCKED, userId)
                    : null;
            return new ValidationResponseDTO(userId, false, error);
        } else {
            updatedClaims.put(Constants.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM, String.valueOf(currentAttempts + 1));
            setUserClaimValues(user, updatedClaims);
            return null;
        }
    }

    private Map<String, String> getUserClaimValues(User user, String[] claims) throws EmailOtpServerException {

        try {
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) EmailOtpServiceDataHolder
                    .getInstance().getRealmService().getTenantUserRealm(getTenantId()).getUserStoreManager();
            return userStoreManager.getUserClaimValues(user.getDomainQualifiedUsername(), claims,
                    UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            log.error("Error while reading user claims.", e);
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR,
                    String.format("Failed to read user claims for user ID : %s.", user.getUserID()), e);
        }
    }

    private void setUserClaimValues(User user, Map<String, String> updatedClaims) throws EmailOtpServerException {

        try {
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) EmailOtpServiceDataHolder
                    .getInstance().getRealmService().getTenantUserRealm(getTenantId()).getUserStoreManager();
            userStoreManager.setUserClaimValues(user.getDomainQualifiedUsername(), updatedClaims,
                    UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            log.error("Error while updating user claims", e);
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR,
                    String.format("Failed to update user claims for user ID: %s.", user.getUserID()), e);
        }
    }

    private User getUserById(String userId) throws EmailOtpException {

        try {
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) EmailOtpServiceDataHolder
                    .getInstance().getRealmService().getTenantUserRealm(getTenantId()).getUserStoreManager();
            return userStoreManager.getUser(userId, null);
        } catch (UserStoreException e) {
            // Handle user not found.
            String errorCode = ((org.wso2.carbon.user.core.UserStoreException) e).getErrorCode();
            if (UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER.getCode().equals(errorCode)) {
                throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_INVALID_USER_ID, userId);
            }
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR,
                    String.format("Error while retrieving user for the ID : %s.", userId), e);
        }
    }
}
