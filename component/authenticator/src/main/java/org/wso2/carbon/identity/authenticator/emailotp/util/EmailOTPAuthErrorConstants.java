/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.authenticator.emailotp.util;

/**
 * Error constants of EmailOTP.
 */
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
