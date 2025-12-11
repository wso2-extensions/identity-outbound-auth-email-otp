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

package org.wso2.carbon.identity.extension.emailotp.common.test;

import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.extension.identity.emailotp.common.constant.Constants;
import org.wso2.carbon.extension.identity.emailotp.common.exception.EmailOtpClientException;
import org.wso2.carbon.extension.identity.emailotp.common.exception.EmailOtpServerException;
import org.wso2.carbon.extension.identity.emailotp.common.util.Utils;

public class UtilsTest {

    @BeforeMethod
    public void setUp() {

        MockitoAnnotations.initMocks(this);
    }

    @AfterMethod
    public void tearDown() {

    }

    @Test
    public void testHandleClientException() {

        String data = "sample data";
        EmailOtpClientException exception =
                Utils.handleClientException(Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED, data);
        Assert.assertEquals(exception.getErrorCode(), Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED.getCode());
        Assert.assertEquals(exception.getMessage(), Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED.getMessage());
        Assert.assertEquals(exception.getDescription(),
                String.format(Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED.getDescription(), data));
    }

    @Test
    public void testHandleClientExceptionWithThrowable() {

        String data = "sample data";
        Exception e = new Exception();
        EmailOtpClientException exception =
                Utils.handleClientException(Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED, data, e);
        Assert.assertEquals(exception.getErrorCode(), Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED.getCode());
        Assert.assertEquals(exception.getMessage(), Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED.getMessage());
        Assert.assertEquals(exception.getCause(), e);
        Assert.assertEquals(exception.getDescription(),
                String.format(Constants.ErrorMessage.CLIENT_OTP_VALIDATION_FAILED.getDescription(), data));
    }

    @Test
    public void testHandleServerException() {

        String data = "sample data";
        EmailOtpServerException exception =
                Utils.handleServerException(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR, data);
        Assert.assertEquals(exception.getErrorCode(), Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR.getCode());
        Assert.assertEquals(exception.getMessage(), Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR.getMessage());
        Assert.assertEquals(exception.getDescription(),
                String.format(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR.getDescription(), data));
    }

    @Test
    public void testHandleServerExceptionWithThrowable() {

        String data = "sample data";
        Exception e = new Exception();
        EmailOtpServerException exception =
                Utils.handleServerException(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR, data, e);
        Assert.assertEquals(exception.getErrorCode(), Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR.getCode());
        Assert.assertEquals(exception.getMessage(), Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR.getMessage());
        Assert.assertEquals(exception.getCause(), e);
        Assert.assertEquals(exception.getDescription(),
                String.format(Constants.ErrorMessage.SERVER_USER_STORE_MANAGER_ERROR.getDescription(), data));
    }
}
