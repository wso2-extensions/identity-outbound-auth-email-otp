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

package org.wso2.carbon.extension.identity.emailotp.common.constant;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Email OTP service constants.
 */
public class Constants {

    public static final String ALGORITHM_NAME = "DRBG";
    public static final String ALGORITHM_HMAC = "HmacSHA256";
    public static final String ALGORITHM_HMAC_SHA = "HMAC-SHA-256";
    public static final String SESSION_TYPE_OTP = "EMAIL_OTP";
    public static final String NOTIFICATION_TYPE_EMAIL_OTP = "EmailOTP";
    public static final String OTP_CODE = "OTPCode";

    public static final int NUMBER_BASE = 2;
    public static final int DEFAULT_OTP_LENGTH = 6;

    public static final int DEFAULT_EMAIL_OTP_EXPIRY_TIME = 120000;
    public static final int DEFAULT_EMAIL_RESEND_THROTTLE_INTERVAL = 30000;

    public static final String EMAIL_OTP_IDENTITY_EVENT_MODULE_NAME = "emailOtp";
    public static final String EMAIL_OTP_ENABLED = "emailOtp.enabled";
    public static final String EMAIL_OTP_LENGTH = "emailOtp.tokenLength";
    public static final String EMAIL_OTP_VALIDITY_PERIOD = "emailOtp.tokenValidityPeriod";
    public static final String EMAIL_OTP_ALPHA_NUMERIC_OTP = "emailOtp.isEnableAlphanumericToken";
    public static final String EMAIL_OTP_TRIGGER_OTP_NOTIFICATION = "emailOtp.triggerNotification";
    public static final String EMAIL_OTP_RENEWAL_INTERVAL = "emailOtp.tokenRenewalInterval";
    public static final String EMAIL_OTP_RESEND_THROTTLE_INTERVAL = "emailOtp.resendThrottleInterval";
    public static final String EMAIL_OTP_SHOW_FAILURE_REASON = "emailOtp.showValidationFailureReason";
    public static final String EMAIL_OTP_MULTIPLE_SESSIONS_ENABLED = "emailOtp.isEnableMultipleSessions";
    public static final String EMAIL_OTP_LOCK_ACCOUNT_ON_FAILED_ATTEMPTS = "emailOtp.lockAccountOnFailedAttempts";

    public static final String PROPERTY_LOGIN_FAIL_TIMEOUT_RATIO = "account.lock.handler.login.fail.timeout.ratio";
    public static final String PROPERTY_ACCOUNT_LOCK_ON_FAILURE = "account.lock.handler.enable";
    public static final String PROPERTY_ACCOUNT_LOCK_ON_FAILURE_MAX = "account.lock.handler.On.Failure.Max.Attempts";
    public static final String PROPERTY_ACCOUNT_LOCK_TIME = "account.lock.handler.Time";
    public static final String EMAIL_OTP_FAILED_ATTEMPTS_CLAIM =
            "http://wso2.org/claims/identity/failedEmailOtpAttempts";
    public static final String FAILED_LOGIN_LOCKOUT_COUNT_CLAIM =
            "http://wso2.org/claims/identity/failedLoginLockoutCount";
    public static final String ACCOUNT_LOCKED_CLAIM = "http://wso2.org/claims/identity/accountLocked";
    public static final String ACCOUNT_UNLOCK_TIME_CLAIM = "http://wso2.org/claims/identity/unlockTime";
    public static final String ACCOUNT_LOCKED_REASON_CLAIM_URI = "http://wso2.org/claims/identity/lockedReason";
    public static final String MAX_EMAIL_OTP_ATTEMPTS_EXCEEDED = "MAX_EMAIL_OTP_ATTEMPTS_EXCEEDED";
    public static final String ADMIN_INITIATED = "AdminInitiated";

    /**
     * EMAIL OTP service error codes.
     */
    public enum ErrorMessage {

        // Client error codes.
        CLIENT_BAD_REQUEST("EMAIL-60001", "Bad request.", "Bad request : %s."),
        CLIENT_EMPTY_USER_ID("EMAIL-60002", "Provided user ID is empty.",
                "Provided user ID is empty."),
        CLIENT_INVALID_USER_ID("EMAIL-60003", "Invalid user Id.",
                "Provided user ID is invalid : %s."),
        CLIENT_BLANK_EMAIL_ADDRESS("EMAIL-60004", "Invalid email address.",
                "No valid email address for the user : %s."),
        CLIENT_EXPIRED_OTP("EMAIL-60005", "Expired OTP.", "Expired OTP."),
        CLIENT_INVALID_TRANSACTION_ID("EMAIL-60006", "Invalid transaction Id.",
                "Invalid transaction Id."),
        CLIENT_MANDATORY_VALIDATION_PARAMETERS_EMPTY("EMAIL-60007", "Mandatory parameters not found.",
                "Mandatory parameters not found : %s."),
        CLIENT_OTP_USER_VALIDATION_FAILED("EMAIL-60008", "OTP user validation failed.",
                "Provided OTP doesn't belong to the mentioned user : %s."),
        CLIENT_OTP_VALIDATION_FAILED("EMAIL-60009", "Provided OTP is invalid.",
                "Provided OTP is invalid for the user ID: %s."),
        CLIENT_SLOW_DOWN_RESEND("EMAIL-60010", "Slow down.",
                "Please wait %s seconds before retrying."),
        CLIENT_NO_OTP_FOR_USER("EMAIL-60011", "No OTP found for the user.",
                "No OTP found for the user Id : %s."),
        CLIENT_ACCOUNT_LOCKED("EMAIL-60012", "Account locked.",
                "Account is locked for the user ID: %s."),

        // Server error codes.
        SERVER_USER_STORE_MANAGER_ERROR("EMAIL-65001", "User store manager error.",
                "User store manager error : %s."),
        SERVER_RETRIEVING_EMAIL_ERROR("EMAIL-65002", "User store manager error.",
                "Error retrieving email address of the user : %s."),
        SERVER_GENERATE_ALPHA_NUMERIC_OTP_ERROR("EMAIL-65003", "Error generating alpha numeric OTP.",
                "Error generating alpha numeric OTP : %s."),
        SERVER_GENERATE_OTP_ERROR("EMAIL-65004", "Error generating the OTP.",
                "Error generating the OTP : %s."),
        SERVER_SESSION_JSON_MAPPER_ERROR("EMAIL-65005", "Error parsing to JSON.",
                "Error parsing to JSON : %s."),
        SERVER_NOTIFICATION_SENDING_ERROR("EMAIL-65006", "Error while sending the notification.",
                "Error while sending the EMAIL notification to the user : %s."),
        SERVER_JSON_SESSION_MAPPER_ERROR("EMAIL-65007", "Error parsing to sessionDTO.",
                "Error parsing to SessionDTO."),
        SERVER_EVENT_CONFIG_LOADING_ERROR("EMAIL-65008", "Error while loading EMAIL OTP event configs.",
                "Error while loading EMAIL OTP event configs : %s"),
        SERVER_INCOMPATIBLE_USER_STORE_MANAGER_ERROR("EMAIL-65009", "Incompatible user store manager.",
                "user store manager doesn't support unique Ids."),
        SERVER_INVALID_RENEWAL_INTERVAL_ERROR("EMAIL-65010", "Invalid renewal interval value.",
                "Renewal interval should be smaller than the OTP validity period. Renewal interval: %s."),
        SERVER_UNEXPECTED_ERROR("EMAIL-65011", "An unexpected server error occurred.",
                "An unexpected server error occurred."),
        SERVER_ERROR_VALIDATING_ACCOUNT_LOCK_STATUS("EMAIL-65012", "Error validating account lock status.",
                "Server encountered an error while validating account lock status for the user ID : %s."),
        SERVER_ERROR_RETRIEVING_ACCOUNT_LOCK_CONFIGS("EMAIL-65013", "Can't retrieve account lock connector " +
                "configurations.", "Server encountered an error while retrieving account lock connector configurations.");

        private final String code;
        private final String message;
        private final String description;

        ErrorMessage(String code, String message, String description) {

            this.code = code;
            this.message = message;
            this.description = description;
        }

        public String getCode() {

            return code;
        }

        public String getMessage() {

            return message;
        }

        public String getDescription() {

            return description;
        }

        public String toString() {

            return getCode() + " | " + message;
        }
    }

    // Forbidden error codes.
    private static List<String> forbiddenErrors = new ArrayList<>();
    // Conflict error codes.
    private static List<String> conflictErrors = new ArrayList<>();
    // Not Found error codes.
    private static List<String> notFoundErrors = Arrays.asList(ErrorMessage.CLIENT_INVALID_USER_ID.code);

    /**
     * This is to check if the error is a Forbidden Error.
     *
     * @param errorCode Error code of the error.
     * @return True if it is a forbidden error if not False.
     */
    public static boolean isForbiddenError(String errorCode) {

        return forbiddenErrors.contains(errorCode);
    }

    /**
     * This is to check if the error is a Conflict Error.
     *
     * @param errorCode Error code of the error.
     * @return True if it is a Conflict error if not False.
     */
    public static boolean isConflictError(String errorCode) {

        return conflictErrors.contains(errorCode);
    }

    /**
     * This is to check if the error is a Not found Error.
     *
     * @param errorCode Error code of the error.
     * @return True if it is a Not found error if not False.
     */
    public static boolean isNotFoundError(String errorCode) {

        return notFoundErrors.contains(errorCode);
    }
}
