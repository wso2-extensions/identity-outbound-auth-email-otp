/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.extension.identity.emailotp.common;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.extension.identity.emailotp.common.constant.Constants;
import org.wso2.carbon.extension.identity.emailotp.common.dto.GenerationResponseDTO;
import org.wso2.carbon.extension.identity.emailotp.common.dto.SessionDTO;
import org.wso2.carbon.extension.identity.emailotp.common.dto.ValidationResponseDTO;
import org.wso2.carbon.extension.identity.emailotp.common.exception.EmailOtpException;
import org.wso2.carbon.extension.identity.emailotp.common.exception.EmailOtpServerException;
import org.wso2.carbon.extension.identity.emailotp.common.internal.EmailOtpServiceDataHolder;
import org.wso2.carbon.extension.identity.emailotp.common.util.OneTimePasswordUtils;
import org.wso2.carbon.extension.identity.emailotp.common.util.Utils;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.event.IdentityEventConfigBuilder;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.ModuleConfiguration;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannels;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.identity.recovery.internal.IdentityRecoveryServiceDataHolder;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.user.core.common.User;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

/**
 * This class implements the {@link EmailOtpService} interface.
 */
public class EmailOtpServiceImpl implements EmailOtpService {

    private static final Log log = LogFactory.getLog(EmailOtpService.class);

    @Override
    public GenerationResponseDTO generateEmailOTP(String userId) throws EmailOtpException {

        if (org.apache.commons.lang3.StringUtils.isBlank(userId)) {
            throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_EMPTY_USER_ID, null);
        }
        // Retrieve user by ID.
        UniqueIDUserStoreManager userStoreManager;
        User user;
        try {
            UserStoreManager manager = EmailOtpServiceDataHolder.getInstance()
                    .getRealmService().getTenantUserRealm(getTenantId()).getUserStoreManager();
            if (manager instanceof UniqueIDUserStoreManager) {
                userStoreManager = (UniqueIDUserStoreManager) manager;
            } else {
                throw Utils.handleClientException(Constants.ErrorMessage.SERVER_INCOMPATIBLE_USER_STORE_MANAGER_ERROR, null);
            }
            user = userStoreManager.getUserWithID(userId, null, null);
        } catch (UserStoreException e) {
            // Handle user not found.
            if ("30007".equals(((org.wso2.carbon.user.core.UserStoreException) e).getErrorCode())) {
                throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_INVALID_USER_ID, userId);
            }
            throw Utils.handleClientException(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR,
                    "Error while retrieving user from the Id : " + userId, e);
        }
        // Check if the user exist.
        if (user == null) {
            throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_INVALID_USER_ID, userId);
        }

        String emailAddress = getEmailAddress(user.getUsername(), userStoreManager);

        SessionDTO sessionDTO = proceedWithOTP(emailAddress, user);

        GenerationResponseDTO otpDto = new GenerationResponseDTO();
        otpDto.setTransactionId(sessionDTO.getTransactionId());
        otpDto.setEmailOTP(sessionDTO.getOtpToken());
        return otpDto;
    }

    @Override
    public ValidationResponseDTO validateEmailOTP(String transactionId, String userId, String emailOTP)
            throws EmailOtpException {

        // Sanitize inputs.
        if (org.apache.commons.lang3.StringUtils.isBlank(transactionId) ||
                org.apache.commons.lang3.StringUtils.isBlank(userId) ||
                org.apache.commons.lang3.StringUtils.isBlank(emailOTP)) {
            String missingParam = org.apache.commons.lang3.StringUtils.isBlank(transactionId) ? "transactionId"
                    : org.apache.commons.lang3.StringUtils.isBlank(userId) ? "userId"
                    : "emailOTP";
            throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_MANDATORY_VALIDATION_PARAMETERS_EMPTY, missingParam);
        }
        transactionId = transactionId.trim();
        userId = userId.trim();
        emailOTP = emailOTP.trim();

        // Checking if resendSameOtpEnabled.
        Properties properties = readConfigurations();
        String otpExpiryTimeValue = org.apache.commons.lang3.StringUtils.trim(properties
                .getProperty(Constants.OTP_EXPIRY_TIME_PROPERTY));
        String otpRenewalIntervalValue = org.apache.commons.lang3.StringUtils.trim(properties
                .getProperty(Constants.OTP_RENEWAL_INTERVAL));
        // If not defined, use the default values.
        int otpExpiryTime = org.apache.commons.lang3.StringUtils.isNumeric(otpExpiryTimeValue) ?
                Integer.parseInt(otpExpiryTimeValue) : Constants.DEFAULT_EMAIL_OTP_EXPIRY_TIME;
        // If not defined, defaults to zero to renew always.
        int otpRenewalInterval = org.apache.commons.lang3.StringUtils.isNumeric(otpRenewalIntervalValue) ?
                Integer.parseInt(otpRenewalIntervalValue) : 0;
        boolean resendSameOtpEnabled = otpRenewalInterval > 0 && otpRenewalInterval < otpExpiryTime;

        // Retrieve session from the database.
        String sessionId = resendSameOtpEnabled ? String.valueOf(userId.hashCode()) : transactionId;
        String jsonString = (String) SessionDataStore.getInstance()
                .getSessionData(sessionId, Constants.SESSION_TYPE_OTP);
        if (org.apache.commons.lang3.StringUtils.isBlank(jsonString)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Invalid transaction Id provided for the user : %s.", userId));
            }
            return new ValidationResponseDTO(userId, false);
        }
        ObjectMapper mapper = new ObjectMapper();
        SessionDTO sessionDTO;
        try {
            sessionDTO = mapper.readValue(jsonString, SessionDTO.class);
        } catch (IOException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_JSON_SESSION_MAPPER_ERROR, null, e);
        }

        // Check if the provided OTP is correct.
        if (!org.apache.commons.lang3.StringUtils.equals(emailOTP, sessionDTO.getOtpToken())) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Invalid OTP provided for the user : %s.", userId));
            }
            return new ValidationResponseDTO(userId, false);
        }
        // Check for expired OTPs.
        if (System.currentTimeMillis() - sessionDTO.getGeneratedTime() >= sessionDTO.getExpiryTime()) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Expired OTP provided for the user : %s.", userId));
            }
            return new ValidationResponseDTO(userId, false);
        }
        // Check if the OTP belongs to the provided user.
        if (!org.apache.commons.lang3.StringUtils.equals(userId, sessionDTO.getUserId())) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("OTP doesn't belong to the provided user. User : %s.", userId));
            }
            return new ValidationResponseDTO(userId, false);
        }
        // Check if the provided transaction Id is correct.
        if (!org.apache.commons.lang3.StringUtils.equals(transactionId, sessionDTO.getTransactionId())) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Provided transaction Id doesn't match. User : %s.", userId));
            }
            return new ValidationResponseDTO(userId, false);
        }
        // Valid OTP.
        // Clear OTP session data.
        SessionDataStore.getInstance().clearSessionData(sessionId, Constants.SESSION_TYPE_OTP);
        return new ValidationResponseDTO(userId, true);
    }

    private SessionDTO proceedWithOTP(String emailAddress, User user) throws EmailOtpException {

        // Read server configurations.
        Properties properties = readConfigurations();
        String otpLengthValue = org.apache.commons.lang3.StringUtils.trim(properties
                .getProperty(Constants.OTP_LENGTH_PROPERTY));
        String otpExpiryTimeValue = org.apache.commons.lang3.StringUtils.trim(properties
                .getProperty(Constants.OTP_EXPIRY_TIME_PROPERTY));
        String otpRenewIntervalValue = org.apache.commons.lang3.StringUtils.trim(properties
                .getProperty(Constants.OTP_RENEWAL_INTERVAL));
        boolean isAlphaNumericOtpEnabled = Boolean.parseBoolean(
                properties.getProperty(Constants.ALPHA_NUMERIC_OTP_PROPERTY));
        // Notification sending defaults to false.
        boolean triggerNotification =
                org.apache.commons.lang3.StringUtils.isNotBlank(properties
                        .getProperty(Constants.TRIGGER_OTP_NOTIFICATION_PROPERTY)) &&
                        Boolean.parseBoolean(properties.getProperty(Constants.TRIGGER_OTP_NOTIFICATION_PROPERTY));

        // If not defined, use the default values.
        int otpExpiryTime = org.apache.commons.lang3.StringUtils.isNumeric(otpExpiryTimeValue) ?
                Integer.parseInt(otpExpiryTimeValue) : Constants.DEFAULT_EMAIL_OTP_EXPIRY_TIME;
        int otpLength = org.apache.commons.lang3.StringUtils.isNumeric(otpLengthValue) ?
                Integer.parseInt(otpLengthValue) : Constants.DEFAULT_OTP_LENGTH;
        // If not defined, defaults to zero to renew always.
        int otpRenewalInterval = org.apache.commons.lang3.StringUtils.isNumeric(otpRenewIntervalValue) ?
                Integer.parseInt(otpRenewIntervalValue) : 0;
        // Should we send the same OTP when asked to resend.
        boolean resendSameOtpEnabled = otpRenewalInterval > 0 && otpRenewalInterval < otpExpiryTime;

        // If 'resending same OTP' is enabled, check if such exists.
        SessionDTO sessionDTO = resendSameOtpEnabled ?
                getPreviousValidSession(user.getUserID(), otpRenewalInterval) : null;

        // Otherwise generate a new OTP and proceed.
        if (sessionDTO == null) {
            // Generate OTP.
            String transactionId = createTransactionId();
            String otp = OneTimePasswordUtils.generateToken(
                    transactionId,
                    String.valueOf(Constants.NUMBER_BASE),
                    otpLength);
            // Save the otp in the IDN_AUTH_SESSION_STORE table.
            sessionDTO = new SessionDTO();
            sessionDTO.setOtpToken(otp);
            sessionDTO.setGeneratedTime(System.currentTimeMillis());
            sessionDTO.setExpiryTime(otpExpiryTime);
            sessionDTO.setTransactionId(transactionId);
            sessionDTO.setFullQualifiedUserName(user.getFullQualifiedUsername());
            sessionDTO.setUserId(user.getUserID());
            String jsonString;
            try {
                jsonString = new ObjectMapper().writeValueAsString(sessionDTO);
            } catch (JsonProcessingException e) {
                throw Utils.handleServerException(Constants.ErrorMessage.SERVER_SESSION_JSON_MAPPER_ERROR, e.getMessage(), e);
            }
            String sessionId = resendSameOtpEnabled ? String.valueOf(user.getUserID().hashCode()) : transactionId;
            SessionDataStore.getInstance().storeSessionData(sessionId, Constants.SESSION_TYPE_OTP, jsonString,
                    getTenantId());
            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully persisted the OTP for the user : %s.",
                        sessionDTO.getFullQualifiedUserName()));
            }
        }

        // Sending EMAIL notifications.
        if (triggerNotification) {
            triggerNotification(user, emailAddress, sessionDTO.getOtpToken());
        }
        return sessionDTO;
    }

    private void triggerNotification(User user, String emailAddress, String otpCode) throws EmailOtpException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Sending %s notification to : %s.", Constants.NOTIFICATION_TYPE_EMAIL_OTP,
                    user.getFullQualifiedUsername())
            );
        }
        if (org.apache.commons.lang3.StringUtils.isBlank(emailAddress)) {
            throw Utils.handleClientException(Constants.ErrorMessage.CLIENT_BLANK_EMAIL_ADDRESS, user.getFullQualifiedUsername());
        }

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUsername());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
        properties.put(IdentityEventConstants.EventProperty.NOTIFICATION_CHANNEL,
                NotificationChannels.EMAIL_CHANNEL.getChannelType());
        properties.put(IdentityRecoveryConstants.TEMPLATE_TYPE, Constants.NOTIFICATION_TYPE_EMAIL_OTP);
        properties.put(IdentityRecoveryConstants.SEND_TO, emailAddress);
        properties.put(IdentityRecoveryConstants.OTP_CODE, otpCode);

        Event event = new Event(IdentityEventConstants.Event.TRIGGER_NOTIFICATION, properties);
        try {
            IdentityRecoveryServiceDataHolder.getInstance().getIdentityEventService().handleEvent(event);
        } catch (IdentityEventException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_NOTIFICATION_SENDING_ERROR, user.getFullQualifiedUsername(), e);
        }
    }

    private String getEmailAddress(String username, UserStoreManager userStoreManager) throws EmailOtpServerException {

        Map<String, String> emailAddressMap;
        try {
            emailAddressMap = userStoreManager.getUserClaimValues(username,
                    new String[]{IdentityRecoveryConstants.EMAIL_ADDRESS_CLAIM}, null);
        } catch (UserStoreException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_RETRIEVING_EMAIL_ERROR, username, e);
        }
        if (MapUtils.isEmpty(emailAddressMap)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No email address found for the user : %s.", username));
            }
            return null;
        }
        return emailAddressMap.get(IdentityRecoveryConstants.EMAIL_ADDRESS_CLAIM);
    }

    private SessionDTO getPreviousValidSession(String userId, int otpRenewalInterval) throws EmailOtpException {

        // Search previous session object.
        String jsonString = (String) SessionDataStore.getInstance().
                getSessionData(String.valueOf(userId.hashCode()), Constants.SESSION_TYPE_OTP);
        if (StringUtils.isBlank(jsonString)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No valid sessions found for the user : %s.", userId));
            }
            return null;
        }
        ObjectMapper mapper = new ObjectMapper();
        SessionDTO previousSessionDTO;
        try {
            previousSessionDTO = mapper.readValue(jsonString, SessionDTO.class);
        } catch (IOException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_JSON_SESSION_MAPPER_ERROR, null, e);
        }
        // If the previous OTP is issued within the interval, return the same.
        return (System.currentTimeMillis() - previousSessionDTO.getGeneratedTime() < otpRenewalInterval) ?
                previousSessionDTO : null;
    }

    private Properties readConfigurations() throws EmailOtpServerException {

        try {
            ModuleConfiguration configs = IdentityEventConfigBuilder.getInstance()
                    .getModuleConfigurations(Constants.EMAIL_OTP_IDENTITY_EVENT_MODULE_NAME);
            // Work with the default values if configurations couldn't be loaded.
            return configs != null ? configs.getModuleProperties() : new Properties();
        } catch (IdentityEventException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_EVENT_CONFIG_LOADING_ERROR,
                    Constants.EMAIL_OTP_IDENTITY_EVENT_MODULE_NAME, e);
        }
    }

    private String createTransactionId() {

        String transactionId = UUID.randomUUID().toString();
        if (log.isDebugEnabled()) {
            log.debug("Transaction Id: " + transactionId);
        }
        return transactionId;
    }

    private int getTenantId() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
    }
}
