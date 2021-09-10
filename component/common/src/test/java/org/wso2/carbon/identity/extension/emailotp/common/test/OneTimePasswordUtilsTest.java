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
import org.powermock.api.mockito.PowerMockito;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.extension.identity.emailotp.common.constant.Constants;
import org.wso2.carbon.extension.identity.emailotp.common.util.OneTimePasswordUtils;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class OneTimePasswordUtilsTest {

    private OneTimePasswordUtils oneTimePasswordUtils;

    @BeforeMethod
    public void setUp() {

        oneTimePasswordUtils = new OneTimePasswordUtils();
        MockitoAnnotations.initMocks(this);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new PowerMockObjectFactory();
    }

    @AfterMethod
    public void tearDown() {

    }

    @Test
    public void testCalcChecksum() {

        Assert.assertEquals(oneTimePasswordUtils.calcChecksum(100, 10), 8);
    }

    @Test
    public void testGetRandomNumber() {

        Assert.assertNotNull(oneTimePasswordUtils.getRandomNumber(10));
    }

    @Test
    public void testHmacShaGenerate() throws InvalidKeyException, NoSuchAlgorithmException {

        String input = "Hello World";
        byte[] bytes = input.getBytes(Charset.forName("UTF-8"));
        byte[] answer = oneTimePasswordUtils.hmacShaGenerate(bytes, bytes);
        String s = new String(answer, Charset.forName("UTF-8"));
        Assert.assertNotNull(oneTimePasswordUtils.hmacShaGenerate(bytes, bytes));
    }

    @Test
    public void testGenerateOTPWithNumericToken() throws Exception {

        OneTimePasswordUtils otp = PowerMockito.spy(oneTimePasswordUtils);
        Assert.assertEquals(Whitebox.invokeMethod(otp, "generateOTP",
                "6f7698e7-d76a-4dee-ad0a-794b04c33572",
                String.valueOf(Constants.NUMBER_BASE),
                Constants.DEFAULT_OTP_LENGTH,
                false),
                "900361");
    }

    @Test
    public void testGenerateOTPWithAlphaNumericToken() throws Exception {

        OneTimePasswordUtils otp = PowerMockito.spy(oneTimePasswordUtils);
        Assert.assertEquals(Whitebox.invokeMethod(otp, "generateOTP",
                "6f7698e7-d76a-4dee-ad0a-794b04c33572",
                String.valueOf(Constants.NUMBER_BASE),
                Constants.DEFAULT_OTP_LENGTH,
                true),
                "W5GG7P");
    }
}
