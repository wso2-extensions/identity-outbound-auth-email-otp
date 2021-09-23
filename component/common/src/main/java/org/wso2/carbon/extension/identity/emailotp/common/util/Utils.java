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

package org.wso2.carbon.extension.identity.emailotp.common.util;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.emailotp.common.constant.Constants;
import org.wso2.carbon.extension.identity.emailotp.common.dto.ConfigsDTO;
import org.wso2.carbon.extension.identity.emailotp.common.exception.EmailOtpClientException;
import org.wso2.carbon.extension.identity.emailotp.common.exception.EmailOtpServerException;
import org.wso2.carbon.extension.identity.emailotp.common.internal.EmailOtpServiceDataHolder;
import org.wso2.carbon.identity.event.IdentityEventConfigBuilder;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.ModuleConfiguration;

import java.util.Properties;
import java.util.UUID;

/**
 * Util functions for Email OTP service.
 */
public class Utils {

    private static final Log log = LogFactory.getLog(Utils.class);

    /**
     * Read configurations and populate {@link ConfigsDTO} object.
     *
     * @throws EmailOtpServerException Throws upon an issue while reading configs.
     */
    public static void readConfigurations() throws EmailOtpServerException {

        Properties properties;
        try {
            ModuleConfiguration configs = IdentityEventConfigBuilder.getInstance()
                    .getModuleConfigurations(Constants.EMAIL_OTP_IDENTITY_EVENT_MODULE_NAME);
            if (configs != null) {
                properties = configs.getModuleProperties();
            } else {
                properties = new Properties();
                log.debug("Couldn't find Email OTP handler configurations.");
            }
            sanitizeAndPopulateConfigs(properties);
        } catch (IdentityEventException e) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_EVENT_CONFIG_LOADING_ERROR,
                    Constants.EMAIL_OTP_IDENTITY_EVENT_MODULE_NAME, e);
        }
        log.debug(String.format("Email OTP service configurations : %s.",
                EmailOtpServiceDataHolder.getConfigs().toString()));
    }

    private static void sanitizeAndPopulateConfigs(Properties properties) throws EmailOtpServerException {

        ConfigsDTO configs = EmailOtpServiceDataHolder.getConfigs();

        boolean isEnabled = Boolean.parseBoolean(StringUtils.trim(
                properties.getProperty(Constants.EMAIL_OTP_ENABLED)));
        configs.setEnabled(isEnabled);

        // Defaults to 'false'.
        boolean triggerNotification = Boolean.parseBoolean(StringUtils.trim(
                properties.getProperty(Constants.EMAIL_OTP_TRIGGER_OTP_NOTIFICATION)));
        configs.setTriggerNotification(triggerNotification);

        boolean showFailureReason = Boolean.parseBoolean(StringUtils.trim(
                properties.getProperty(Constants.EMAIL_OTP_SHOW_FAILURE_REASON)));
        configs.setShowFailureReason(showFailureReason);

        boolean isAlphaNumericOtp = Boolean.parseBoolean(StringUtils.trim(
                properties.getProperty(Constants.EMAIL_OTP_ALPHA_NUMERIC_OTP)));
        configs.setAlphaNumericOTP(isAlphaNumericOtp);

        String otpLengthValue = StringUtils.trim(properties.getProperty(
                Constants.EMAIL_OTP_LENGTH));
        int otpLength = StringUtils.isNumeric(otpLengthValue) ?
                Integer.parseInt(otpLengthValue) : Constants.DEFAULT_OTP_LENGTH;
        configs.setOtpLength(otpLength);

        String otpValidityPeriodValue =
                StringUtils.trim(properties.getProperty(Constants.EMAIL_OTP_VALIDITY_PERIOD));
        int otpValidityPeriod = StringUtils.isNumeric(otpValidityPeriodValue) ?
                Integer.parseInt(otpValidityPeriodValue) * 1000 : Constants.DEFAULT_EMAIL_OTP_EXPIRY_TIME;
        configs.setOtpValidityPeriod(otpValidityPeriod);

        // If not defined, defaults to 'zero' to renew always.
        String otpRenewIntervalValue = StringUtils.trim(
                properties.getProperty(Constants.EMAIL_OTP_RENEWAL_INTERVAL));
        int otpRenewalInterval = StringUtils.isNumeric(otpRenewIntervalValue) ?
                Integer.parseInt(otpRenewIntervalValue) * 1000 : 0;
        configs.setOtpRenewalInterval(otpRenewalInterval);

        if (otpRenewalInterval >= otpValidityPeriod) {
            throw Utils.handleServerException(Constants.ErrorMessage.SERVER_INVALID_RENEWAL_INTERVAL_ERROR,
                    String.valueOf(otpRenewalInterval));
        }

        String otpResendThrottleIntervalValue = StringUtils.trim(
                properties.getProperty(Constants.EMAIL_OTP_RESEND_THROTTLE_INTERVAL));
        int resendThrottleInterval = StringUtils.isNumeric(otpResendThrottleIntervalValue) ?
                Integer.parseInt(otpResendThrottleIntervalValue) * 1000 :
                Constants.DEFAULT_EMAIL_RESEND_THROTTLE_INTERVAL;
        configs.setResendThrottleInterval(resendThrottleInterval);

        // Should we send the same OTP upon the next generation request? Defaults to 'false'.
        boolean resendSameOtp = (otpRenewalInterval > 0) && (otpRenewalInterval < otpValidityPeriod);
        configs.setResendSameOtp(resendSameOtp);

        // Defaults to 'true' with an interval of 30 seconds.
        boolean resendThrottlingEnabled = resendThrottleInterval > 0;
        configs.setResendThrottlingEnabled(resendThrottlingEnabled);
    }

    public static String getHash(String text) {

        return DigestUtils.sha256Hex(text);
    }

    public static String createTransactionId() {

        String transactionId = UUID.randomUUID().toString();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Transaction Id hash: %s.", transactionId.hashCode()));
        }
        return transactionId;
    }

    public static EmailOtpClientException handleClientException(Constants.ErrorMessage error, String data) {

        String description;
        if (StringUtils.isNotBlank(data)) {
            description = String.format(error.getDescription(), data);
        } else {
            description = error.getDescription();
        }
        return new EmailOtpClientException(error.getMessage(), description, error.getCode());
    }

    public static EmailOtpClientException handleClientException(Constants.ErrorMessage error, String data,
                                                                Throwable e) {

        String description;
        if (StringUtils.isNotBlank(data)) {
            description = String.format(error.getDescription(), data);
        } else {
            description = error.getDescription();
        }
        return new EmailOtpClientException(error.getMessage(), description, error.getCode(), e);
    }

    public static EmailOtpServerException handleServerException(Constants.ErrorMessage error, String data,
                                                                Throwable e) {

        String description;
        if (StringUtils.isNotBlank(data)) {
            description = String.format(error.getDescription(), data);
        } else {
            description = error.getDescription();
        }
        return new EmailOtpServerException(error.getMessage(), description, error.getCode(), e);
    }

    public static EmailOtpServerException handleServerException(Constants.ErrorMessage error, String data) {

        String description;
        if (StringUtils.isNotBlank(data)) {
            description = String.format(error.getDescription(), data);
        } else {
            description = error.getDescription();
        }
        return new EmailOtpServerException(error.getMessage(), description, error.getCode());
    }
}