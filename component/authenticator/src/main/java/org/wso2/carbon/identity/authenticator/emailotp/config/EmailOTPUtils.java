/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.authenticator.emailotp.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorConstants;
import java.util.Collections;
import java.util.Map;

/**
 * Providing configuration required for the Authenticator.
 */
public class EmailOTPUtils {

    private static Log log = LogFactory.getLog(EmailOTPUtils.class);

    /**
     * Get parameter values from application-authentication.xml file.
     */
    public static Map<String, String> getEmailParameters() {

        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (authConfig != null) {
            return authConfig.getParameterMap();
        }
        if (log.isDebugEnabled()) {
            log.debug("Authenticator config related to given config name not found. Hence returning an empty map");
        }
        return Collections.emptyMap();

    }

    /**
     * Get the corresponding configuration from Email parameters.
     *
     * @param context    Authentication Context.
     * @param configName Name of the config.
     * @return Config value.
     */
    public static String getConfiguration(AuthenticationContext context, String configName) {

        String configValue = null;
        if (getEmailParameters().containsKey(configName)) {
            configValue = getEmailParameters().get(configName);
        } else if ((context.getProperty(configName)) != null) {
            configValue = String.valueOf(context.getProperty(configName));
        }
        if (log.isDebugEnabled()) {
            log.debug("Config value for key " + configName + ": " + configValue);
        }
        return configValue;
    }
}
