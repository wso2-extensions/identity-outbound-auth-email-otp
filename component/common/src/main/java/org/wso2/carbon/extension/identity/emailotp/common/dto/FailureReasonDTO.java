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

package org.wso2.carbon.extension.identity.emailotp.common.dto;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.extension.identity.emailotp.common.constant.Constants;

/**
 * This class represents the model of the OTP validation
 * failure reason message, if any.
 */
public class FailureReasonDTO {

    String code;
    String message;
    String description;
    int remainingAttempts;

    public FailureReasonDTO(String code, String message, String description) {

        this.code = code;
        this.message = message;
        this.description = description;
        this.remainingAttempts = 0;
    }

    public FailureReasonDTO(String code, String message, String description, int remainingAttempts) {

        this.code = code;
        this.message = message;
        this.description = description;
        this.remainingAttempts = remainingAttempts;
    }

    public FailureReasonDTO(Constants.ErrorMessage error, String data) {

        this.code = error.getCode();
        this.message = error.getMessage();
        description = StringUtils.isNotBlank(data) ? String.format(error.getDescription(), data)
                : error.getDescription();
        this.remainingAttempts = 0;
    }

    /**
     * This method composes the error message for failed sms-otp validation attempts.
     *
     * @param error                     Error message.
     * @param data                      Data passed for the string argument in error message.
     * @param remainingFailedAttempts   No of remaining validation attempts.
     */
    public FailureReasonDTO(Constants.ErrorMessage error, String data, int remainingFailedAttempts) {

        this.code = error.getCode();
        this.message = error.getMessage();
        description = StringUtils.isNotBlank(data) ? String.format(error.getDescription(), data)
                : error.getDescription();
        this.remainingAttempts = remainingFailedAttempts;
    }

    public String getCode() {

        return code;
    }

    public void setCode(String code) {

        this.code = code;
    }

    public String getMessage() {

        return message;
    }

    public void setMessage(String message) {

        this.message = message;
    }

    public String getDescription() {

        return description;
    }

    public void setDescription(String description) {

        this.description = description;
    }

    public int getRemainingAttempts() {

        return remainingAttempts;
    }

    public void setRemainingAttempts(int remainingAttempts) {

        this.remainingAttempts = remainingAttempts;
    }
}
