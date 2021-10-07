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
 * This class holds the Email OTP feature configurations.
 */
public class ConfigsDTO {

    private boolean isEnabled;
    private boolean showFailureReason;
    private boolean isAlphaNumericOTP;
    private boolean triggerNotification;
    private boolean resendSameOtp;
    private boolean resendThrottlingEnabled;
    private int otpLength;
    private int otpValidityPeriod;
    private int otpRenewalInterval;
    private int resendThrottleInterval;

    public boolean isEnabled() {

        return isEnabled;
    }

    public void setEnabled(boolean enabled) {

        isEnabled = enabled;
    }

    public boolean isShowFailureReason() {

        return showFailureReason;
    }

    public void setShowFailureReason(boolean showFailureReason) {

        this.showFailureReason = showFailureReason;
    }

    public boolean isAlphaNumericOTP() {

        return isAlphaNumericOTP;
    }

    public void setAlphaNumericOTP(boolean alphaNumericOTP) {

        isAlphaNumericOTP = alphaNumericOTP;
    }

    public boolean isTriggerNotification() {

        return triggerNotification;
    }

    public void setTriggerNotification(boolean triggerNotification) {

        this.triggerNotification = triggerNotification;
    }

    public boolean isResendSameOtp() {

        return resendSameOtp;
    }

    public void setResendSameOtp(boolean resendSameOtp) {

        this.resendSameOtp = resendSameOtp;
    }

    public boolean isResendThrottlingEnabled() {

        return resendThrottlingEnabled;
    }

    public void setResendThrottlingEnabled(boolean resendThrottlingEnabled) {

        this.resendThrottlingEnabled = resendThrottlingEnabled;
    }

    public int getOtpLength() {

        return otpLength;
    }

    public void setOtpLength(int otpLength) {

        this.otpLength = otpLength;
    }

    public int getOtpValidityPeriod() {

        return otpValidityPeriod;
    }

    public void setOtpValidityPeriod(int otpValidityPeriod) {

        this.otpValidityPeriod = otpValidityPeriod;
    }

    public int getOtpRenewalInterval() {

        return otpRenewalInterval;
    }

    public void setOtpRenewalInterval(int otpRenewalInterval) {

        this.otpRenewalInterval = otpRenewalInterval;
    }

    public int getResendThrottleInterval() {

        return resendThrottleInterval;
    }

    public void setResendThrottleInterval(int resendThrottleInterval) {

        this.resendThrottleInterval = resendThrottleInterval;
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder("ConfigsDTO {");
        sb.append("\n\tisEnabled = ").append(isEnabled)
                .append(",\n\tshowFailureReason = ").append(showFailureReason)
                .append(",\n\tisAlphaNumericOTP = ").append(isAlphaNumericOTP)
                .append(",\n\ttriggerNotification = ").append(triggerNotification)
                .append(",\n\tresendSameOtp = ").append(resendSameOtp)
                .append(",\n\tresendThrottlingEnabled = ").append(resendThrottlingEnabled)
                .append(",\n\totpLength = ").append(otpLength)
                .append(",\n\totpValidityPeriod = ").append(otpValidityPeriod)
                .append(",\n\totpRenewalInterval = ").append(otpRenewalInterval)
                .append(",\n\tresendThrottleInterval = ").append(resendThrottleInterval)
                .append("\n}");
        return sb.toString();
    }
}
