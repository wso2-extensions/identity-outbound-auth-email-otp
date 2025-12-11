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
import org.wso2.carbon.extension.identity.emailotp.common.util.OneTimePasswordUtils;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class OneTimePasswordUtilsTest {

    @BeforeMethod
    public void setUp() {

        MockitoAnnotations.initMocks(this);
    }

    @AfterMethod
    public void tearDown() {

    }

    @Test
    public void testCalcChecksum() {

        Assert.assertEquals(OneTimePasswordUtils.calcChecksum(100, 10), 8);
    }

    @Test
    public void testGetRandomNumber() {

        Assert.assertNotNull(OneTimePasswordUtils.getRandomNumber(10));
    }

    @Test
    public void testHmacShaGenerate() throws InvalidKeyException, NoSuchAlgorithmException {

        String input = "Hello World";
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        Assert.assertNotNull(OneTimePasswordUtils.hmacShaGenerate(bytes, bytes));
    }

    @Test
    public void testGenerateOTPWithNumericToken() throws Exception {

        Method generateOTPMethod = OneTimePasswordUtils.class.getDeclaredMethod("generateOTP",
                String.class, String.class, int.class, boolean.class);
        generateOTPMethod.setAccessible(true);

        String result = (String) generateOTPMethod.invoke(null,
                "6f7698e7-d76a-4dee-ad0a-794b04c33572",
                String.valueOf(Constants.NUMBER_BASE),
                Constants.DEFAULT_OTP_LENGTH,
                false);

        Assert.assertEquals(result, "673418");
    }

    @Test
    public void testGenerateOTPWithAlphaNumericToken() throws Exception {

        Method generateOTPMethod = OneTimePasswordUtils.class.getDeclaredMethod("generateOTP",
                String.class, String.class, int.class, boolean.class);
        generateOTPMethod.setAccessible(true);

        String result = (String) generateOTPMethod.invoke(null,
                "6f7698e7-d76a-4dee-ad0a-794b04c33572",
                String.valueOf(Constants.NUMBER_BASE),
                Constants.DEFAULT_OTP_LENGTH,
                true);

        Assert.assertEquals(result, "2B0A7V");
    }
}
