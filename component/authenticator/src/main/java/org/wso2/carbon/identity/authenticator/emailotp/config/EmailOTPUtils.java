package org.wso2.carbon.identity.authenticator.emailotp.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorConstants;

import java.util.Collections;
import java.util.Map;

public class EmailOTPUtils {

    private static Log log = LogFactory.getLog(EmailOTPUtils.class);

    /**
     * Get parameter values from application-authentication.xml local file.
     */
    public static Map<String, String> getEmailParameters() {

        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (authConfig != null) {
            return authConfig.getParameterMap();
        }
        if (log.isDebugEnabled()) {
            log.debug("Authenticator configs not found. Hence returning an empty map");
        }
        return Collections.emptyMap();

    }
    /**
     * Read configurations from application-authentication.xml for given authenticator.
     *
     * @param context    Authentication Context.
     * @param configName Name of the config.
     * @return Config value.
     */
    public static String getConfiguration(AuthenticationContext context, String configName) {

        String configValue = null;
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        String tenantDomain = context.getTenantDomain();
        if ((propertiesFromLocal == null || getEmailParameters().containsKey(configName)) ){
            configValue = getEmailParameters().get(configName);
        } else if ((context.getProperty(configName)) != null) {
            configValue = String.valueOf(context.getProperty(configName));
        }
        if (log.isDebugEnabled()) {
            log.debug("Config value for key " + configName + " for tenant " + tenantDomain + " : " +
                    configValue);
        }
        return configValue;
    }

    public static String getExpirationTimeAttribute(AuthenticationContext context) {

        return getConfiguration(context, EmailOTPAuthenticatorConstants.OTP_EXPIRE_TIME_IN_MILIS);
    }


}