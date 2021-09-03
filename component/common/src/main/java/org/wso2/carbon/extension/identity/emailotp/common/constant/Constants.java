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

package org.wso2.carbon.extension.identity.emailotp.common.constant;

/**
 * EMAIL OTP service constants.
 */

public class Constants {

    public static final String CORRELATION_ID_MDC = "Correlation-ID";
    public static final String ALGORITHM_NAME = "SHA1PRNG";
    public static final String ALGORITHM_HMAC = "HmacSHA1";
    public static final String ALGORITHM_HMAC_SHA = "HMAC-SHA-1";
    public static final String SESSION_TYPE_OTP = "EMAIL_OTP";
    public static final String NOTIFICATION_TYPE_EMAIL_OTP = "EmailOTP";

    public static final int NUMBER_BASE = 2;
    public static final int DEFAULT_OTP_LENGTH = 6;

    public static final int DEFAULT_EMAIL_OTP_EXPIRY_TIME = 120000;

    public static final String EMAIL_OTP_IDENTITY_EVENT_MODULE_NAME = "emailOtp";
    public static final String OTP_LENGTH_PROPERTY = "emailOtp.tokenLength";
    public static final String OTP_EXPIRY_TIME_PROPERTY = "emailOtp.tokenExpiryTime";
    public static final String ALPHA_NUMERIC_OTP_PROPERTY = "emailOtp.isEnableAlphanumericToken";
    public static final String TRIGGER_OTP_NOTIFICATION_PROPERTY = "emailOtp.triggerNotification";
    public static final String OTP_RENEWAL_INTERVAL = "emailOtp.tokenRenewInterval";

    /**
     * EMAIL OTP service error codes.
     */
    public enum ErrorMessage {

        // Client error codes.
        CLIENT_BAD_REQUEST("EMAIL-60001", "Bad request.", "Bad request : %s."),
        CLIENT_EMPTY_USER_ID("EMAIL-60002", "Provided user ID is empty.", "Provided user ID is empty."),
        CLIENT_INVALID_USER_ID("EMAIL-60003", "Invalid user Id.", "Provided user ID is invalid : %s."),
        CLIENT_BLANK_EMAIL_ADDRESS("EMAIL-60004", "Invalid email address.",
                "No valid email address for the user : %s."),
        CLIENT_EXPIRED_OTP("EMAIL-60005", "Expired OTP.",
                "Expired OTP."),
        CLIENT_INVALID_TRANSACTION_ID("EMAIL-60006", "Invalid transaction Id.",
                "Invalid transaction Id."),
        CLIENT_MANDATORY_VALIDATION_PARAMETERS_EMPTY("EMAIL-60007", "Mandatory parameters not found.",
                "Mandatory parameters not found : %s."),
        CLIENT_OTP_USER_VALIDATION_FAILED("EMAIL-60007", "OTP user validation failed.",
                "Provided OTP doesn't belong to the mentioned user : %s."),
        CLIENT_OTP_VALIDATION_FAILED("EMAIL-60008", "Provided OTP is invalid.",
                "Provided OTP is invalid."),

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
        SERVER_UNEXPECTED_ERROR("EMAIL-65010", "An unexpected server error occurred.",
                "An unexpected server error occurred.");

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

    /**
     * Forbidden Error Messages
     */
    public enum ForbiddenErrorMessages {

    }

    /**
     * Not Found Error Messages
     */
    public enum NotFoundErrorMessages {

        EMAIL_60003
    }

    /**
     * Conflict Error Messages
     */
    public enum ConflictErrorMessages {

    }
}
