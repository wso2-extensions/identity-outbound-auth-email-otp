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

/**
 * This class represents a model of to validate Email OTP response.
 */
public class ValidationResponseDTO {

    private boolean isValid;
    private String userId;
    private FailureReasonDTO failureReason;

    public ValidationResponseDTO(String userId, boolean isValid) {

        this.isValid = isValid;
        this.userId = userId;
    }

    public ValidationResponseDTO(String userId, boolean isValid, FailureReasonDTO failureReason) {

        this.isValid = isValid;
        this.userId = userId;
        this.failureReason = failureReason;
    }

    public boolean isValid() {

        return isValid;
    }

    public void setValid(boolean valid) {

        isValid = valid;
    }

    public String getUserId() {

        return userId;
    }

    public void setUserId(String userId) {

        this.userId = userId;
    }

    public FailureReasonDTO getFailureReason() {

        return failureReason;
    }

    public void setFailureReason(FailureReasonDTO failureReason) {

        this.failureReason = failureReason;
    }
}
