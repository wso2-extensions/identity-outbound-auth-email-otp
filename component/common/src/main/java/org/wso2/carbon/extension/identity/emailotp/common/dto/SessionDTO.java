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

import java.io.Serializable;
import java.util.Objects;

/**
 * Object used to save the data in the database.
 */
public class SessionDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    private String otpToken;
    private long generatedTime;
    private long expiryTime;
    private String transactionId;
    private String fullQualifiedUserName;
    private String userId;
    private int validationAttempts;

    public String getOtpToken() {

        return otpToken;
    }

    public void setOtpToken(String otpToken) {

        this.otpToken = otpToken;
    }

    public long getGeneratedTime() {

        return generatedTime;
    }

    public void setGeneratedTime(long generatedTime) {

        this.generatedTime = generatedTime;
    }

    public long getExpiryTime() {

        return expiryTime;
    }

    public void setExpiryTime(long expiryTime) {

        this.expiryTime = expiryTime;
    }

    public String getTransactionId() {

        return transactionId;
    }

    public void setTransactionId(String transactionId) {

        this.transactionId = transactionId;
    }

    public String getFullQualifiedUserName() {

        return fullQualifiedUserName;
    }

    public void setFullQualifiedUserName(String fullQualifiedUserName) {

        this.fullQualifiedUserName = fullQualifiedUserName;
    }

    public String getUserId() {

        return userId;
    }

    public void setUserId(String userId) {

        this.userId = userId;
    }

    public int getValidationAttempts() {

        return validationAttempts;
    }

    public void setValidationAttempts(int validationAttempts) {

        this.validationAttempts = validationAttempts;
    }

    @Override
    public boolean equals(Object o) {

        if (this == o) {
            return true;
        }
        if (!(o instanceof SessionDTO)) {
            return false;
        }
        SessionDTO that = (SessionDTO) o;
        return getGeneratedTime() == that.getGeneratedTime() &&
                getExpiryTime() == that.getExpiryTime() &&
                getOtpToken().equals(that.getOtpToken()) &&
                getTransactionId().equals(that.getTransactionId()) &&
                getFullQualifiedUserName().equals(that.getFullQualifiedUserName()) &&
                getUserId().equals(that.getUserId()) &&
                getValidationAttempts() == that.getValidationAttempts();
    }

    @Override
    public int hashCode() {

        return Objects.hash(getOtpToken(), getGeneratedTime(), getExpiryTime(), getTransactionId(),
                getFullQualifiedUserName(), getUserId(), getValidationAttempts());
    }

    @Override
    public String toString() {

        return "SessionDTO{" +
                "otpToken='" + otpToken + '\'' +
                ", generatedTime=" + generatedTime +
                ", expiryTime=" + expiryTime +
                ", transactionId='" + transactionId + '\'' +
                ", fullQualifiedUserName='" + fullQualifiedUserName + '\'' +
                ", userId='" + userId + '\'' +
                ", validationAttempts='" + validationAttempts + '\'' +
                '}';
    }
}
