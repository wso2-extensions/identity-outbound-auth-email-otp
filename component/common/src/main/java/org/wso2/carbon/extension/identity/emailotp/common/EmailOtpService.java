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

package org.wso2.carbon.extension.identity.emailotp.common;

import org.wso2.carbon.extension.identity.emailotp.common.dto.GenerationResponseDTO;
import org.wso2.carbon.extension.identity.emailotp.common.dto.ValidationResponseDTO;
import org.wso2.carbon.extension.identity.emailotp.common.exception.EmailOtpException;

/**
 * EmailOtpService interface.
 */
public interface EmailOtpService {

    /**
     * This method validates a provided OTP.
     *
     * @param transactionId UUID to track the flow.
     * @param userId        SCIM User Id.
     * @param emailOTP      OTP to be validated.
     * @return OTP validation result.
     * @throws EmailOtpException Thrown if any server or client error occurred.
     */
    ValidationResponseDTO validateEmailOTP(String transactionId, String userId, String emailOTP) throws
            EmailOtpException;

    /**
     * This method verify a provided OTP without invalidate.
     *
     * @param transactionId UUID to track the flow.
     * @param userId        SCIM User Id.
     * @param emailOTP      OTP to be validated.
     * @return OTP verification result.
     * @throws EmailOtpException Thrown if any server or client error occurred.
     */
    ValidationResponseDTO verifyEmailOTP(String transactionId, String userId, String emailOTP) throws
            EmailOtpException;

    /**
     * This method will generate an OTP and send an EMAIL notification.
     *
     * @param userId SCIM User Id.
     * @return OTP generation response.
     * @throws EmailOtpException Thrown if any server or client error occurred.
     */
    GenerationResponseDTO generateEmailOTP(String userId) throws EmailOtpException;
}

