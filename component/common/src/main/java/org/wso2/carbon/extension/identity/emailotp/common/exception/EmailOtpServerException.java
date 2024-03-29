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

package org.wso2.carbon.extension.identity.emailotp.common.exception;

/**
 * This class is to handle Email OTP server exception
 */
public class EmailOtpServerException extends EmailOtpException {

    public EmailOtpServerException(String errorCode, String message) {

        super(errorCode, message);
    }

    public EmailOtpServerException(String errorCode, String message, Throwable throwable) {

        super(errorCode, message, throwable);
    }

    public EmailOtpServerException(String message, String description, String errorCode) {

        super(message, description, errorCode);
    }

    public EmailOtpServerException(String message, String description, String errorCode, Throwable e) {

        super(message, description, errorCode, e);
    }
}
