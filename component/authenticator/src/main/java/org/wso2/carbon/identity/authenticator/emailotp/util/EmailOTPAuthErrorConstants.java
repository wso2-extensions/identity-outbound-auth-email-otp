package org.wso2.carbon.identity.authenticator.emailotp.util;

public class EmailOTPAuthErrorConstants {

    /**
     * Authentication error constants of EmailOTP Authenticator.
     */
    public enum ErrorMessages {

        // Identifier related Error codes.
        EMPTY_USERNAME("BAS-60002", "Username is empty."),

        // IO related Error codes
        SYSTEM_ERROR_WHILE_AUTHENTICATING("BAS-65001", "System error while authenticating");

        private final String code;
        private final String message;

        /**
         * Create an Error Message.
         *
         * @param code    Relevant error code.
         * @param message Relevant error message.
         */
        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        /**
         * To get the code of specific error.
         *
         * @return Error code.
         */
        public String getCode() {

            return code;
        }

        /**
         * To get the message of specific error.
         *
         * @return Error message.
         */
        public String getMessage() {

            return message;
        }
    }
}
