/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.emailotp.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticator;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.identity.captcha.util.CaptchaConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import java.util.Hashtable;

/**
 * Email OTP service component.
 */
@Component(
        name = "identity.application.authenticator.emailotp.component",
        immediate = true
)
public class EmailOTPAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(EmailOTPAuthenticatorServiceComponent.class);

    protected void activate(ComponentContext ctxt) {

        buildReCaptchaFilterProperties();
        try {
            EmailOTPAuthenticator authenticator = new EmailOTPAuthenticator();
            Hashtable<String, String> props = new Hashtable<>();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    authenticator, props);
            if (log.isDebugEnabled()) {
                log.debug("EmailOTP authenticator is activated");
            }
        } catch (Throwable e) {
            log.fatal("Error while activating the EmailOTP authenticator ", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("EmailOTP authenticator is deactivated");
        }
    }

    @Reference(
            name = "EventMgtService",
            service = org.wso2.carbon.identity.event.services.IdentityEventService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityEventService")
    protected void setIdentityEventService(IdentityEventService eventService) {

        EmailOTPServiceDataHolder.getInstance().setIdentityEventService(eventService);
    }

    protected void unsetIdentityEventService(IdentityEventService eventService) {

        EmailOTPServiceDataHolder.getInstance().setIdentityEventService(null);
    }

    @Reference(
            name = "RealmService",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        EmailOTPServiceDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        EmailOTPServiceDataHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "IdentityGovernanceService",
            service = org.wso2.carbon.identity.governance.IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService"
    )
    protected void setIdentityGovernanceService(IdentityGovernanceService idpManager) {

        EmailOTPServiceDataHolder.getInstance().setIdentityGovernanceService(idpManager);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService idpManager) {

        EmailOTPServiceDataHolder.getInstance().setIdentityGovernanceService(null);
    }

    @Reference(
            name = "AccountLockService",
            service = org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAccountLockService"
    )
    protected void setAccountLockService(AccountLockService accountLockService) {

        EmailOTPServiceDataHolder.getInstance().setAccountLockService(accountLockService);
    }

    protected void unsetAccountLockService(AccountLockService accountLockService) {

        EmailOTPServiceDataHolder.getInstance().setAccountLockService(null);
    }

    /**
     * Read the captcha-config.properties file located in repository/conf/identity directory and set the
     * configurations required to enable recaptcha in the Data holder.
     */
    private void buildReCaptchaFilterProperties() {

        Path path = Paths.get(IdentityUtil.getIdentityConfigDirPath(), CaptchaConstants.CAPTCHA_CONFIG_FILE_NAME);

        if (Files.exists(path)) {
            Properties properties = new Properties();
            try (Reader in = new InputStreamReader(Files.newInputStream(path), StandardCharsets.UTF_8)) {
                properties.load(in);
            } catch (IOException e) {
                log.error("Error while loading '" + CaptchaConstants.CAPTCHA_CONFIG_FILE_NAME + "' configuration " +
                        "file", e);
            }

            boolean reCaptchaEnabled = Boolean.parseBoolean(properties.getProperty(CaptchaConstants
                    .RE_CAPTCHA_ENABLED));

            if (reCaptchaEnabled) {
                EmailOTPServiceDataHolder.getInstance().setRecaptchaConfigs(properties);
            }
        }
    }
}
