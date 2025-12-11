/*
 *  Copyright (c) 2017, WSO2 LLC. (https://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
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
package org.wso2.carbon.identity.authenticator.emailotp;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.description.TransportOutDescription;
import org.apache.axis2.engine.AxisConfiguration;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.authenticator.emailotp.config.EmailOTPUtils;
import org.wso2.carbon.identity.authenticator.emailotp.internal.EmailOTPServiceDataHolder;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.mgt.IdentityMgtConfigException;
import org.wso2.carbon.identity.mgt.IdentityMgtServiceException;
import org.wso2.carbon.identity.mgt.config.Config;
import org.wso2.carbon.identity.mgt.config.ConfigBuilder;
import org.wso2.carbon.identity.mgt.config.ConfigType;
import org.wso2.carbon.identity.mgt.config.StorageType;
import org.wso2.carbon.identity.mgt.mail.Notification;
import org.wso2.carbon.identity.mgt.mail.NotificationBuilder;
import org.wso2.carbon.identity.mgt.mail.NotificationData;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorTestConstants.DUMMY_LOGIN_PAGE_URL;
import static org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorTestConstants.EMAIL_ADDRESS;
import static org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorTestConstants.TENANT_DOMAIN;
import static org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorTestConstants.TENANT_ID;
import static org.wso2.carbon.identity.authenticator.emailotp.EmailOTPAuthenticatorTestConstants.USER_NAME;

public class EmailOTPAuthenticatorTest {
    private EmailOTPAuthenticator emailOTPAuthenticator;
    @Spy
    private AuthenticatorConfig authenticatorConfig;
    @Spy
    private AuthenticationContext context;

    private HttpServletRequest httpServletRequest;
    private EmailOTPAuthenticator mockedEmailOTPAuthenticator;
    private EmailOTPAuthenticator spiedEmailOTPAuthenticator;
    private HttpServletResponse httpServletResponse;
    private FileBasedConfigurationBuilder fileBasedConfigurationBuilder;
    private StepConfig stepConfig;
    private RealmService realmService;
    private UserRealm userRealm;
    private AbstractUserStoreManager userStoreManager;
    private AuthenticatedUser authUser;
    private LocalApplicationAuthenticator localApplicationAuthenticator;
    private ClaimManager claimManager;
    private Claim claim;
    private ConfigurationFacade configurationFacade;
    private ConfigurationContext configurationContext;
    private AxisConfiguration axisConfiguration;
    private ConfigBuilder configBuilder;
    private Config config;
    private HashMap<String, TransportOutDescription> transportOutDescriptionHashMap;
    private Notification notification;
    private FrameworkServiceDataHolder frameworkServiceDataHolder;
    private MultiAttributeLoginService multiAttributeLoginService;

    private MockedStatic<FileBasedConfigurationBuilder> fileBasedConfigurationBuilderMock;
    private MockedStatic<EmailOTPServiceDataHolder> emailOTPServiceDataHolderMock;
    private MockedStatic<FederatedAuthenticatorUtil> federatedAuthenticatorUtilMock;
    private MockedStatic<FrameworkUtils> frameworkUtilsMock;
    private MockedStatic<UserCoreUtil> userCoreUtilMock;
    private MockedStatic<MultitenantUtils> multitenantUtilsMock;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMock;
    private MockedStatic<ConfigurationContextFactory> configurationContextFactoryMock;
    private MockedStatic<ConfigBuilder> configBuilderStaticMock;
    private MockedStatic<NotificationBuilder> notificationBuilderStaticMock;
    private MockedStatic<EmailOTPUtils> emailOTPUtilsMock;
    private MockedStatic<OneTimePassword> oneTimePasswordMock;
    private MockedStatic<ConfigurationFacade> configurationFacadeStaticMock;
    private MockedStatic<FrameworkServiceDataHolder> frameworkServiceDataHolderStaticMock;
    private MockedStatic<ServiceURLBuilder> serviceURLBuilderMock;
    private MockedStatic<IdentityUtil> identityUtilMock;

    @BeforeMethod
    public void setUp() throws Exception {

        emailOTPAuthenticator = new EmailOTPAuthenticator();
        initMocks(this);
        httpServletRequest = mock(HttpServletRequest.class);
        mockedEmailOTPAuthenticator = mock(EmailOTPAuthenticator.class);
        spiedEmailOTPAuthenticator = spy(new EmailOTPAuthenticator());
        httpServletResponse = mock(HttpServletResponse.class);
        fileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);
        stepConfig = mock(StepConfig.class);
        realmService = mock(RealmService.class);
        userRealm = mock(UserRealm.class);
        userStoreManager = mock(AbstractUserStoreManager.class);
        authUser = mock(AuthenticatedUser.class);
        localApplicationAuthenticator = mock(LocalApplicationAuthenticator.class);
        claimManager = mock(ClaimManager.class);
        claim = mock(Claim.class);
        context = spy(new AuthenticationContext());
        configurationFacade = mock(ConfigurationFacade.class);
        configurationContext = mock(ConfigurationContext.class);
        axisConfiguration = mock(AxisConfiguration.class);
        transportOutDescriptionHashMap = mock(HashMap.class);
        configBuilder = mock(ConfigBuilder.class);
        config = mock(Config.class);
        notification = mock(Notification.class);
        frameworkServiceDataHolder = mock(FrameworkServiceDataHolder.class);
        multiAttributeLoginService = mock(MultiAttributeLoginService.class);

        // Initialize static mocks for this test method.
        fileBasedConfigurationBuilderMock = mockStatic(FileBasedConfigurationBuilder.class);
        emailOTPServiceDataHolderMock = mockStatic(EmailOTPServiceDataHolder.class);
        federatedAuthenticatorUtilMock = mockStatic(FederatedAuthenticatorUtil.class);
        frameworkUtilsMock = mockStatic(FrameworkUtils.class);
        userCoreUtilMock = mockStatic(UserCoreUtil.class);
        multitenantUtilsMock = mockStatic(MultitenantUtils.class);
        identityTenantUtilMock = mockStatic(IdentityTenantUtil.class);
        configurationContextFactoryMock = mockStatic(ConfigurationContextFactory.class);
        configBuilderStaticMock = mockStatic(ConfigBuilder.class);
        notificationBuilderStaticMock = mockStatic(NotificationBuilder.class);
        emailOTPUtilsMock = mockStatic(EmailOTPUtils.class);
        oneTimePasswordMock = mockStatic(OneTimePassword.class);
        configurationFacadeStaticMock = mockStatic(ConfigurationFacade.class);
        frameworkServiceDataHolderStaticMock = mockStatic(FrameworkServiceDataHolder.class);
        serviceURLBuilderMock = mockStatic(ServiceURLBuilder.class);
        identityUtilMock = mockStatic(IdentityUtil.class);

        EmailOTPServiceDataHolder emailOTPServiceDataHolder = mock(EmailOTPServiceDataHolder.class);
        IdentityEventService identityEventService = mock(IdentityEventService.class);
        emailOTPServiceDataHolderMock.when(EmailOTPServiceDataHolder::getInstance)
                .thenReturn(emailOTPServiceDataHolder);
        when(emailOTPServiceDataHolder.getIdentityEventService()).thenReturn(identityEventService);
        Mockito.doNothing().when(identityEventService).handleEvent(any());

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(USER_NAME);
        authenticatedUser.setUserStoreDomain("secondary");
        authenticatedUser.setUserId(EmailOTPAuthenticatorTestConstants.USER_ID);
        when(context.getProperty(EmailOTPAuthenticatorConstants.AUTHENTICATED_USER)).thenReturn(authenticatedUser);

        mockServiceURLBuilder();
    }

    @AfterMethod
    public void tearDown() {

        if (fileBasedConfigurationBuilderMock != null) {
            fileBasedConfigurationBuilderMock.close();
        }
        if (emailOTPServiceDataHolderMock != null) {
            emailOTPServiceDataHolderMock.close();
        }
        if (federatedAuthenticatorUtilMock != null) {
            federatedAuthenticatorUtilMock.close();
        }
        if (frameworkUtilsMock != null) {
            frameworkUtilsMock.close();
        }
        if (userCoreUtilMock != null) {
            userCoreUtilMock.close();
        }
        if (multitenantUtilsMock != null) {
            multitenantUtilsMock.close();
        }
        if (identityTenantUtilMock != null) {
            identityTenantUtilMock.close();
        }
        if (configurationContextFactoryMock != null) {
            configurationContextFactoryMock.close();
        }
        if (configBuilderStaticMock != null) {
            configBuilderStaticMock.close();
        }
        if (notificationBuilderStaticMock != null) {
            notificationBuilderStaticMock.close();
        }
        if (emailOTPUtilsMock != null) {
            emailOTPUtilsMock.close();
        }
        if (oneTimePasswordMock != null) {
            oneTimePasswordMock.close();
        }
        if (configurationFacadeStaticMock != null) {
            configurationFacadeStaticMock.close();
        }
        if (frameworkServiceDataHolderStaticMock != null) {
            frameworkServiceDataHolderStaticMock.close();
        }
        if (serviceURLBuilderMock != null) {
            serviceURLBuilderMock.close();
        }
        if (identityUtilMock != null) {
            identityUtilMock.close();
        }
    }

    @Test(description = "Test case for canHandle() method true case.")
    public void testCanHandle() throws Exception {
        when(httpServletRequest.getParameter(EmailOTPAuthenticatorConstants.RESEND)).thenReturn("true");
        Assert.assertTrue(emailOTPAuthenticator.canHandle(httpServletRequest));
    }

    @Test(description = "Test case for canHandle() method false case.")
    public void testCanHandleFalse() throws Exception {
        when(httpServletRequest.getParameter(EmailOTPAuthenticatorConstants.RESEND)).thenReturn(null);
        when(httpServletRequest.getParameter(EmailOTPAuthenticatorConstants.CODE)).thenReturn(null);
        when(httpServletRequest.getParameter(EmailOTPAuthenticatorConstants.EMAIL_ADDRESS)).thenReturn(null);
        when(httpServletRequest.getParameter(EmailOTPAuthenticatorConstants.USER_NAME)).thenReturn(null);
        Assert.assertFalse(emailOTPAuthenticator.canHandle(httpServletRequest));
    }

    @Test(description = "Test case for getContextIdentifier() method.")
    public void testGetContextIdentifier() {
        when(httpServletRequest.getParameter("sessionDataKey")).thenReturn("234567890");
        Assert.assertEquals(emailOTPAuthenticator.getContextIdentifier(httpServletRequest), "234567890");

        when(httpServletRequest.getParameter("sessionDataKey")).thenReturn(null);
        Assert.assertNull(emailOTPAuthenticator.getContextIdentifier(httpServletRequest));
    }

    @Test(description = "Test case for getFriendlyName() method.")
    public void testGetFriendlyName() {
        Assert.assertEquals(emailOTPAuthenticator.getFriendlyName(),
                EmailOTPAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME);
    }

    @Test(description = "Test case for getAuthenticatorName() method.")
    public void testGetName() {
        Assert.assertEquals(emailOTPAuthenticator.getName(), EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
    }

    @Test(description = "Test case for retryAuthenticationEnabled() method.")
    public void testRetryAuthenticationEnabled() throws Exception {
        Assert.assertTrue(EmailOTPAuthenticatorTestHelper.retryAuthenticationEnabled(emailOTPAuthenticator));
    }

    @Test(description = "Test case for successful logout request.")
    public void testProcessLogoutRequest() throws Exception {
        when(context.isLogoutRequest()).thenReturn(true);
        Mockito.doReturn(true).when(mockedEmailOTPAuthenticator).canHandle(httpServletRequest);
        AuthenticatorFlowStatus status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(description = "Test case for process() method when authenticated user is null " +
            "and the username of an existing user is entered into the IdF page.")
    public void testProcessWithoutAuthenticatedUserAndValidUsernameEntered()
            throws Exception {

        Map<String, String> parameters = new HashMap<>();
        parameters.put(EmailOTPAuthenticatorConstants.IS_EMAILOTP_MANDATORY, "true");
        parameters.put(EmailOTPAuthenticatorConstants.SEND_OTP_TO_FEDERATED_EMAIL_ATTRIBUTE, "true");

        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        authenticatorConfig.setParameterMap(parameters);
        setStepConfigWithEmailOTPAuthenticator(authenticatorConfig, context);

        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        fileBasedConfigurationBuilderMock.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        configurationFacadeStaticMock.when(ConfigurationFacade::getInstance).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGE_URL);

        AuthenticatorFlowStatus status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
        Assert.assertTrue(((boolean) context.getProperty(
                EmailOTPAuthenticatorConstants.IS_IDF_INITIATED_FROM_AUTHENTICATOR)));

        // Resolving the user object.
        when(httpServletRequest.getParameter(EmailOTPAuthenticatorConstants.USER_NAME))
                .thenReturn(USER_NAME);
        frameworkUtilsMock.when(() -> FrameworkUtils.preprocessUsername(anyString(), any(AuthenticationContext.class)))
                .thenReturn(USER_NAME + "@" + EmailOTPAuthenticatorConstants.SUPER_TENANT);
        userCoreUtilMock.when(() -> UserCoreUtil.extractDomainFromName(anyString())).thenReturn("PRIMARY");
        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn(USER_NAME);
        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantDomain(anyString()))
                .thenReturn(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        federatedAuthenticatorUtilMock.when(() -> FederatedAuthenticatorUtil.isUserExistInUserStore(anyString()))
                .thenReturn(true);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(EmailOTPAuthenticatorConstants.SUPER_TENANT))
                .thenReturn(TENANT_ID);
        when(userStoreManager.getUserClaimValue(
                USER_NAME,
                EmailOTPAuthenticatorConstants.EMAIL_CLAIM,
                null)).thenReturn(EMAIL_ADDRESS);
        userCoreUtilMock.when(() -> UserCoreUtil.addTenantDomainToEntry(
                USER_NAME,
                EmailOTPAuthenticatorConstants.SUPER_TENANT))
            .thenReturn(
                USER_NAME + "@" + EmailOTPAuthenticatorConstants.SUPER_TENANT);
        mockUserRealm();
        User user = new User(UUID.randomUUID().toString(), USER_NAME, null);
        user.setUserStoreDomain("PRIMARY");
        user.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        List<User> userList = new ArrayList<>();
        userList.add(user);
        mockMultiAttributeLoginService();
        when(userStoreManager.getUserListWithID(USERNAME_CLAIM, USER_NAME, null)).thenReturn(userList);
        mockSendOTP();

        status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
        Assert.assertTrue((Boolean.parseBoolean(String.valueOf(context.getProperty(
                EmailOTPAuthenticatorConstants.IS_REDIRECT_TO_EMAIL_OTP)))));
    }

    @Test(description = "Test case for process() method when authenticated user is null and the username of a" +
            "non existing user is entered into the IdF page.")
    public void testProcessWithoutAuthenticatedUserAndInvalidUsernameEntered() throws Exception {

        Map<String, String> parameters = new HashMap<>();
        parameters.put(EmailOTPAuthenticatorConstants.IS_EMAILOTP_MANDATORY, "true");
        parameters.put(EmailOTPAuthenticatorConstants.SEND_OTP_TO_FEDERATED_EMAIL_ATTRIBUTE, "true");

        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        authenticatorConfig.setParameterMap(parameters);
        setStepConfigWithEmailOTPAuthenticator(authenticatorConfig, context);

        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        fileBasedConfigurationBuilderMock.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        configurationFacadeStaticMock.when(ConfigurationFacade::getInstance).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGE_URL);

        AuthenticatorFlowStatus status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
        Assert.assertTrue((boolean) context.getProperty(
                EmailOTPAuthenticatorConstants.IS_IDF_INITIATED_FROM_AUTHENTICATOR));

        // Resolving the user object.
        when(httpServletRequest.getParameter(EmailOTPAuthenticatorConstants.USER_NAME))
                .thenReturn(USER_NAME);
        frameworkUtilsMock.when(() -> FrameworkUtils.preprocessUsername(anyString(), any(AuthenticationContext.class)))
                .thenReturn(USER_NAME + "@" + TENANT_DOMAIN);
        userCoreUtilMock.when(() -> UserCoreUtil.extractDomainFromName(anyString())).thenReturn("PRIMARY");
        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn(USER_NAME);
        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantDomain(anyString())).thenReturn(TENANT_DOMAIN);
        federatedAuthenticatorUtilMock.when(() -> FederatedAuthenticatorUtil.isUserExistInUserStore(anyString()))
                .thenReturn(false);
        mockUserRealm();
        mockMultiAttributeLoginService();
        when(userStoreManager.getUserListWithID(USERNAME_CLAIM, USER_NAME, null))
                .thenReturn(new ArrayList<User>());

        status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
        Assert.assertTrue((Boolean.parseBoolean(String.valueOf(context.getProperty(
                EmailOTPAuthenticatorConstants.IS_REDIRECT_TO_EMAIL_OTP)))));
    }

    @Test(description = "Test case for process() method when email OTP is optional for local user")
    public void testProcessWithEmailOTPOptional() throws Exception {

        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(EmailOTPAuthenticatorConstants.IS_EMAILOTP_MANDATORY, "false");
        authenticatorConfig.setParameterMap(parameters);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);
        authenticatedUser.setUserName(USER_NAME);
        context.setSubject(authenticatedUser);
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        context.setProperty(EmailOTPAuthenticatorConstants.USER_NAME, USER_NAME);
        fileBasedConfigurationBuilderMock.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        frameworkUtilsMock.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(anyString(), anyString(), 
                        anyString())).thenReturn(null);
        setStepConfigWithBasicAuthenticator(authenticatedUser, authenticatorConfig);
        mockUserRealm();
        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantAwareUsername(USER_NAME))
                .thenReturn(USER_NAME);
        when(userStoreManager.getUserClaimValue(USER_NAME,
                EmailOTPAuthenticatorConstants.EMAIL_CLAIM, null))
                .thenReturn(EMAIL_ADDRESS);
        emailOTPAuthenticator = spy(new EmailOTPAuthenticator());
        // Mocking the random number generation since algorithm DRBG is not supported in java 8. Revert this when
        // source is compatible with java 11.
        oneTimePasswordMock.when(() -> OneTimePassword
                .getRandomNumber(EmailOTPAuthenticatorConstants.SECRET_KEY_LENGTH)).thenReturn("123456");
        mockSendOTP();
        AuthenticatorFlowStatus status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test(description = "Test case for process() method when email OTP is mandatory for local user.")
    public void testProcessWithEmailOTPMandatory() throws Exception {

        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(EmailOTPAuthenticatorConstants.IS_EMAILOTP_MANDATORY, "true");
        authenticatorConfig.setParameterMap(parameters);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);
        authenticatedUser.setUserName(USER_NAME);
        context.setSubject(authenticatedUser);
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        context.setProperty(EmailOTPAuthenticatorConstants.USER_NAME, USER_NAME);
        fileBasedConfigurationBuilderMock.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        frameworkUtilsMock.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(anyString(), anyString(), 
                        anyString())).thenReturn(null);
        setStepConfigWithBasicAuthenticator(authenticatedUser, authenticatorConfig);
        mockUserRealm();
        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantAwareUsername(USER_NAME))
                .thenReturn(USER_NAME);
        when(userStoreManager.getUserClaimValue(USER_NAME,
                EmailOTPAuthenticatorConstants.EMAIL_CLAIM, null))
                .thenReturn(EMAIL_ADDRESS);
        emailOTPAuthenticator = spy(new EmailOTPAuthenticator());
        // Mocking the random number generation since algorithm DRBG is not supported in java 8. Revert this when
        // source is compatible with java 11.
        oneTimePasswordMock.when(() -> OneTimePassword
                .getRandomNumber(EmailOTPAuthenticatorConstants.SECRET_KEY_LENGTH)).thenReturn("123456");
        mockSendOTP();
        AuthenticatorFlowStatus status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test(description = "Test case for process() method when email OTP is mandatory and user disabled email OTP.")
    public void testProcessWhenEmailOTPIsMandatoryAndUserDisabledEmailOTP()
            throws Exception {

        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(EmailOTPAuthenticatorConstants.IS_EMAILOTP_MANDATORY, "true");
        parameters.put(EmailOTPAuthenticatorConstants.IS_EMAILOTP_ENABLE_BY_USER, "true");
        authenticatorConfig.setParameterMap(parameters);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);
        authenticatedUser.setUserName(USER_NAME);
        context.setSubject(authenticatedUser);
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        context.setProperty(EmailOTPAuthenticatorConstants.USER_NAME, USER_NAME);
        fileBasedConfigurationBuilderMock.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        frameworkUtilsMock.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(anyString(), anyString(), 
                        anyString())).thenReturn(null);
        when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
        federatedAuthenticatorUtilMock.when(() -> FederatedAuthenticatorUtil.isUserExistInUserStore(anyString()))
                .thenReturn(true);
        setStepConfigWithBasicAuthenticator(authenticatedUser, authenticatorConfig);
        mockUserRealm();
        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantAwareUsername(USER_NAME))
                .thenReturn(USER_NAME);
        Map<String, String> claimMap = new HashMap<>();
        claimMap.put(EmailOTPAuthenticatorConstants.USER_EMAILOTP_DISABLED_CLAIM_URI, "true");
        when(userStoreManager.getUserClaimValuesWithID(EmailOTPAuthenticatorTestConstants.USER_ID,
                new String[] {EmailOTPAuthenticatorConstants.USER_EMAILOTP_DISABLED_CLAIM_URI}, null))
                .thenReturn(claimMap);
        when(userStoreManager.getUserClaimValue(USER_NAME,
                EmailOTPAuthenticatorConstants.EMAIL_CLAIM, null))
                .thenReturn(EmailOTPAuthenticatorTestConstants.EMAIL_ADDRESS);
        // Mocking the random number generation since algorithm DRBG is not supported in java 8. Revert this when
        // source is compatible with java 11.
        oneTimePasswordMock.when(() -> OneTimePassword
                .getRandomNumber(EmailOTPAuthenticatorConstants.SECRET_KEY_LENGTH)).thenReturn("123456");
        mockSendOTP();
        AuthenticatorFlowStatus status = spiedEmailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test(description = "Test case for process() method when email OTP is mandatory and user enabled email OTP.")
    public void testProcessWhenEmailOTPIsMandatoryAndUserEnabledEmailOTP() throws Exception {

        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(EmailOTPAuthenticatorConstants.IS_EMAILOTP_MANDATORY, "true");
        parameters.put(EmailOTPAuthenticatorConstants.SEND_OTP_TO_FEDERATED_EMAIL_ATTRIBUTE, "true");
        parameters.put(EmailOTPAuthenticatorConstants.IS_EMAILOTP_ENABLE_BY_USER, "true");
        authenticatorConfig.setParameterMap(parameters);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);
        authenticatedUser.setUserName(USER_NAME);
        context.setSubject(authenticatedUser);
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        context.setProperty(EmailOTPAuthenticatorConstants.USER_NAME, USER_NAME);
        fileBasedConfigurationBuilderMock.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        frameworkUtilsMock.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(anyString(), anyString(), 
                        anyString())).thenReturn(null);
        when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
        federatedAuthenticatorUtilMock.when(() -> FederatedAuthenticatorUtil.isUserExistInUserStore(anyString()))
                .thenReturn(true);
        setStepConfigWithBasicAuthenticator(authenticatedUser, authenticatorConfig);
        mockUserRealm();
        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantAwareUsername(USER_NAME))
                .thenReturn(USER_NAME);
        Map<String, String> claimMap = new HashMap<>();
        claimMap.put(EmailOTPAuthenticatorConstants.USER_EMAILOTP_DISABLED_CLAIM_URI, "false");
        when(userStoreManager.getUserClaimValuesWithID(EmailOTPAuthenticatorTestConstants.USER_ID,
                new String[] {EmailOTPAuthenticatorConstants.USER_EMAILOTP_DISABLED_CLAIM_URI}, null))
                .thenReturn(claimMap);
        when(userStoreManager.getUserClaimValue(USER_NAME,
                EmailOTPAuthenticatorConstants.EMAIL_CLAIM, null))
                .thenReturn(EmailOTPAuthenticatorTestConstants.EMAIL_ADDRESS);
        // Mocking the random number generation since algorithm DRBG is not supported in java 8. Revert this when
        // source is compatible with java 11.
        oneTimePasswordMock.when(() -> OneTimePassword
                .getRandomNumber(EmailOTPAuthenticatorConstants.SECRET_KEY_LENGTH)).thenReturn("123456");
        mockSendOTP();
        AuthenticatorFlowStatus status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test(description = "Test case for process() method when email OTP is optional and user disabled email OTP.")
    public void testProcessWhenEmailOTPIsOptionalAndUserDisabledEmailOTP() throws AuthenticationFailedException,
            LogoutFailedException, UserStoreException {

        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(EmailOTPAuthenticatorConstants.IS_EMAILOTP_MANDATORY, "false");
        parameters.put(EmailOTPAuthenticatorConstants.SEND_OTP_TO_FEDERATED_EMAIL_ATTRIBUTE, "true");
        parameters.put(EmailOTPAuthenticatorConstants.IS_EMAILOTP_ENABLE_BY_USER, "true");
        authenticatorConfig.setParameterMap(parameters);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);
        authenticatedUser.setUserName(USER_NAME);
        context.setSubject(authenticatedUser);
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        context.setProperty(EmailOTPAuthenticatorConstants.USER_NAME, USER_NAME);
        fileBasedConfigurationBuilderMock.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        frameworkUtilsMock.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(anyString(), anyString(), 
                        anyString())).thenReturn(null);
        when(stepConfig.getAuthenticatedAutenticator()).thenReturn(authenticatorConfig);
        federatedAuthenticatorUtilMock.when(() -> FederatedAuthenticatorUtil.isUserExistInUserStore(anyString()))
                .thenReturn(true);
        setStepConfigWithBasicAuthenticator(authenticatedUser, authenticatorConfig);
        mockUserRealm();
        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantAwareUsername(USER_NAME))
                .thenReturn(USER_NAME);
        Map<String, String> claimMap = new HashMap<>();
        claimMap.put(EmailOTPAuthenticatorConstants.USER_EMAILOTP_DISABLED_CLAIM_URI, "true");
        when(userStoreManager.getUserClaimValues(USER_NAME,
                new String[] {EmailOTPAuthenticatorConstants.USER_EMAILOTP_DISABLED_CLAIM_URI}, null))
                .thenReturn(claimMap);
        AuthenticatorFlowStatus status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    private void mockUserRealm() throws UserStoreException {
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                .thenReturn(EmailOTPAuthenticatorTestConstants.TENANT_ID);
        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantDomain(anyString()))
                .thenReturn(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                .thenReturn(EmailOTPAuthenticatorTestConstants.TENANT_ID);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        frameworkServiceDataHolderStaticMock.when(FrameworkServiceDataHolder::getInstance)
                .thenReturn(frameworkServiceDataHolder);
        when(frameworkServiceDataHolder.getRealmService()).thenReturn(realmService);
    }

    private void mockMultiAttributeLoginService() {
        frameworkServiceDataHolderStaticMock.when(FrameworkServiceDataHolder::getInstance)
                .thenReturn(frameworkServiceDataHolder);
        when(frameworkServiceDataHolder.getMultiAttributeLoginService()).thenReturn(multiAttributeLoginService);
        when(multiAttributeLoginService.isEnabled(anyString())).thenReturn(false);
    }

    private void mockSendOTP() throws AxisFault, IdentityMgtConfigException, IdentityMgtServiceException {
        configurationContextFactoryMock.when(() -> ConfigurationContextFactory
                        .createConfigurationContextFromFileSystem(null, null))
                .thenReturn(configurationContext);
        when(configurationContext.getAxisConfiguration()).thenReturn(axisConfiguration);
        when(axisConfiguration.getTransportsOut()).thenReturn(transportOutDescriptionHashMap);
        when(transportOutDescriptionHashMap.containsKey(EmailOTPAuthenticatorConstants.TRANSPORT_MAILTO))
                .thenReturn(true);
        configBuilderStaticMock.when(ConfigBuilder::getInstance).thenReturn(configBuilder);
        when(configBuilder.loadConfiguration(ConfigType.EMAIL, StorageType.REGISTRY, TENANT_ID)).thenReturn(config);
        Properties properties = new Properties();
        properties.setProperty(EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME, "Email OTP");
        when(config.getProperties()).thenReturn(properties);
        notificationBuilderStaticMock.when(() -> NotificationBuilder.createNotification(anyString(), anyString(),
                        any(NotificationData.class))).thenReturn(notification);

    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testIsEmailOTPDisableForUserException() throws Exception {
        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantDomain(anyString()))
                .thenReturn(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                .thenReturn(EmailOTPAuthenticatorTestConstants.TENANT_ID);
        identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(null);
        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("isEmailOTPDisableForUser", String.class,
                AuthenticationContext.class, Map.class);
        method.setAccessible(true);
        try {
            method.invoke(emailOTPAuthenticator, anyString(), context, new HashMap<>());
        } catch (InvocationTargetException e) {
            throw (AuthenticationFailedException) e.getTargetException();
        }
    }

    @Test
    public void testIsEmailOTPDisableForUser() throws Exception {
        Map<String, String> parameters = new HashMap<>();
        parameters.put(EmailOTPAuthenticatorConstants.IS_EMAILOTP_ENABLE_BY_USER, "true");
        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantDomain(anyString()))
                .thenReturn(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                .thenReturn(EmailOTPAuthenticatorTestConstants.TENANT_ID);
        identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValue(USER_NAME,
                EmailOTPAuthenticatorConstants.USER_EMAILOTP_DISABLED_CLAIM_URI, null)).thenReturn("true");
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);

        Method method = EmailOTPAuthenticator.class.getDeclaredMethod("isEmailOTPDisableForUser", String.class,
                AuthenticationContext.class, Map.class);
        method.setAccessible(true);
        method.invoke(emailOTPAuthenticator, anyString(), context, parameters);
    }

    @Test(description = "Test case for process() method when email OTP is mandatory for federated user.")
    public void testProcessWhenEmailOTPIsMandatoryWithFederatedEmail() throws Exception {

        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantDomain(anyString()))
                .thenReturn(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                .thenReturn(EmailOTPAuthenticatorTestConstants.TENANT_ID);
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(EmailOTPAuthenticatorConstants.IS_EMAILOTP_MANDATORY, "true");
        parameters.put(EmailOTPAuthenticatorConstants.SEND_OTP_TO_FEDERATED_EMAIL_ATTRIBUTE, "true");
        parameters.put(EmailOTPAuthenticatorConstants.FEDERATED_EMAIL_ATTRIBUTE_KEY, "email");
        parameters.put(EmailOTPAuthenticatorConstants.EMAIL_API, "EmailAPI");
        authenticatorConfig.setParameterMap(parameters);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);
        authenticatedUser.setUserName(USER_NAME);
        context.setSubject(authenticatedUser);
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        context.setProperty(EmailOTPAuthenticatorConstants.USER_NAME, USER_NAME);
        context.setAuthenticatorProperties(parameters);
        identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        fileBasedConfigurationBuilderMock.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        frameworkUtilsMock.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(anyString(), anyString(), 
                        anyString())).thenReturn(null);
        setStepConfigWithFederatedAuthenticator(authenticatedUser, authenticatorConfig);
        mockFederatedEmailAttributeKey(parameters, authenticatedUser, EMAIL_ADDRESS);
        emailOTPAuthenticator = spy(new EmailOTPAuthenticator());
        // Mocking the random number generation since algorithm DRBG is not supported in java 8.
        oneTimePasswordMock.when(() -> OneTimePassword
                .getRandomNumber(EmailOTPAuthenticatorConstants.SECRET_KEY_LENGTH)).thenReturn("123456");
        mockSendOTP();

        AuthenticatorFlowStatus status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test(description = "Test case for process() method when email OTP is optional for federated user.")
    public void testProcessWhenEmailOTPIsOptionalWithFederatedEmail() throws Exception {

        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantDomain(anyString()))
                .thenReturn(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                .thenReturn(EmailOTPAuthenticatorTestConstants.TENANT_ID);
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(EmailOTPAuthenticatorConstants.IS_EMAILOTP_MANDATORY, "false");
        parameters.put(EmailOTPAuthenticatorConstants.SEND_OTP_TO_FEDERATED_EMAIL_ATTRIBUTE, "true");
        parameters.put(EmailOTPAuthenticatorConstants.FEDERATED_EMAIL_ATTRIBUTE_KEY, "email");
        parameters.put(EmailOTPAuthenticatorConstants.EMAIL_API, "EmailAPI");
        authenticatorConfig.setParameterMap(parameters);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);
        authenticatedUser.setUserName(USER_NAME);
        context.setSubject(authenticatedUser);
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        context.setProperty(EmailOTPAuthenticatorConstants.USER_NAME, USER_NAME);
        context.setAuthenticatorProperties(parameters);
        identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        fileBasedConfigurationBuilderMock.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        frameworkUtilsMock.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(anyString(), anyString(), 
                        anyString())).thenReturn(null);
        setStepConfigWithFederatedAuthenticator(authenticatedUser, authenticatorConfig);
        mockFederatedEmailAttributeKey(parameters, authenticatedUser, EmailOTPAuthenticatorTestConstants.EMAIL_ADDRESS);
        // Mocking the random number generation since algorithm DRBG is not supported in java 8.
        oneTimePasswordMock.when(() -> OneTimePassword
                .getRandomNumber(EmailOTPAuthenticatorConstants.SECRET_KEY_LENGTH)).thenReturn("123456");
        mockSendOTP();
        emailOTPAuthenticator = spy(new EmailOTPAuthenticator());

        AuthenticatorFlowStatus status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test(description = "Test case for process() method when email OTP is mandatory for federated user and email " +
            "attribute is not available.", expectedExceptions = AuthenticationFailedException.class)
    public void testProcessWhenEmailOTPIsMandatoryWithoutFederatedEmail() throws AuthenticationFailedException,
            LogoutFailedException, UserStoreException {

        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantDomain(anyString()))
                .thenReturn(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                .thenReturn(EmailOTPAuthenticatorTestConstants.TENANT_ID);
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(EmailOTPAuthenticatorConstants.IS_EMAILOTP_MANDATORY, "true");
        parameters.put(EmailOTPAuthenticatorConstants.SEND_OTP_TO_FEDERATED_EMAIL_ATTRIBUTE, "true");
        parameters.put(EmailOTPAuthenticatorConstants.EMAIL_API, "EmailAPI");
        authenticatorConfig.setParameterMap(parameters);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);
        authenticatedUser.setUserName(USER_NAME);
        context.setSubject(authenticatedUser);
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        context.setProperty(EmailOTPAuthenticatorConstants.USER_NAME, USER_NAME);
        context.setAuthenticatorProperties(parameters);
        federatedAuthenticatorUtilMock.when(() -> FederatedAuthenticatorUtil.isUserExistInUserStore(anyString()))
                .thenReturn(true);
        fileBasedConfigurationBuilderMock.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        frameworkUtilsMock.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(anyString(), anyString(), 
                        anyString())).thenReturn(null);
        setStepConfigWithFederatedAuthenticator(authenticatedUser, authenticatorConfig);
        mockFederatedEmailAttributeKey(parameters, authenticatedUser, EMAIL_ADDRESS);
        emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
    }

    @Test(description = "Test case for process() method when email OTP is optional and federated email attribute is " +
            "not available.")
    public void testProcessWhenEmailOTPIsOptionalWithoutFederatedEmail() throws AuthenticationFailedException,
            LogoutFailedException, UserStoreException {

        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantDomain(anyString()))
                .thenReturn(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                .thenReturn(EmailOTPAuthenticatorTestConstants.TENANT_ID);
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(EmailOTPAuthenticatorConstants.IS_EMAILOTP_MANDATORY, "false");
        parameters.put(EmailOTPAuthenticatorConstants.SEND_OTP_TO_FEDERATED_EMAIL_ATTRIBUTE, "true");
        parameters.put(EmailOTPAuthenticatorConstants.EMAIL_API, "EmailAPI");
        authenticatorConfig.setParameterMap(parameters);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);
        authenticatedUser.setUserName(USER_NAME);
        context.setSubject(authenticatedUser);
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        context.setProperty(EmailOTPAuthenticatorConstants.USER_NAME, USER_NAME);
        context.setAuthenticatorProperties(parameters);
        federatedAuthenticatorUtilMock.when(() -> FederatedAuthenticatorUtil.isUserExistInUserStore(anyString()))
                .thenReturn(true);
        identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        fileBasedConfigurationBuilderMock.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        frameworkUtilsMock.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(anyString(), anyString(), 
                        anyString())).thenReturn(null);
        setStepConfigWithFederatedAuthenticator(authenticatedUser, authenticatorConfig);
        mockFederatedEmailAttributeKey(parameters, authenticatedUser, EMAIL_ADDRESS);
        AuthenticatorFlowStatus status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(description = "Test case for process() method when email OTP is Mandatory and send OTP to federated " +
            "email attribute is diabled.", expectedExceptions = AuthenticationFailedException.class)
    public void testProcessWhenEmailOTPIsMandatoryWithoutSendOTPToFederatedEmail() throws AuthenticationFailedException,
            LogoutFailedException, UserStoreException {

        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantDomain(anyString()))
                .thenReturn(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                .thenReturn(EmailOTPAuthenticatorTestConstants.TENANT_ID);
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(EmailOTPAuthenticatorConstants.IS_EMAILOTP_MANDATORY, "true");
        parameters.put(EmailOTPAuthenticatorConstants.SEND_OTP_TO_FEDERATED_EMAIL_ATTRIBUTE, "false");
        parameters.put(EmailOTPAuthenticatorConstants.FEDERATED_EMAIL_ATTRIBUTE_KEY, "email");
        parameters.put(EmailOTPAuthenticatorConstants.EMAIL_API, "EmailAPI");
        authenticatorConfig.setParameterMap(parameters);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);
        authenticatedUser.setUserName(USER_NAME);
        context.setSubject(authenticatedUser);
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        context.setProperty(EmailOTPAuthenticatorConstants.USER_NAME, USER_NAME);
        context.setAuthenticatorProperties(parameters);
        federatedAuthenticatorUtilMock.when(() -> FederatedAuthenticatorUtil.isUserExistInUserStore(anyString()))
                .thenReturn(true);
        fileBasedConfigurationBuilderMock.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        frameworkUtilsMock.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(anyString(), anyString(), 
                        anyString())).thenReturn(null);
        setStepConfigWithFederatedAuthenticator(authenticatedUser, authenticatorConfig);
        mockFederatedEmailAttributeKey(parameters, authenticatedUser, EMAIL_ADDRESS);
        emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
    }

    @Test(description = "Test case for process() method when email OTP is Optional and send OTP to federated " +
            "email attribute is diabled.")
    public void testProcessWhenEmailOTPIsOptionalWithoutSendOTPToFederatedEmail() throws AuthenticationFailedException,
            LogoutFailedException, UserStoreException {

        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantDomain(anyString()))
                .thenReturn(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                .thenReturn(EmailOTPAuthenticatorTestConstants.TENANT_ID);
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(EmailOTPAuthenticatorConstants.IS_EMAILOTP_MANDATORY, "false");
        parameters.put(EmailOTPAuthenticatorConstants.SEND_OTP_TO_FEDERATED_EMAIL_ATTRIBUTE, "false");
        parameters.put(EmailOTPAuthenticatorConstants.FEDERATED_EMAIL_ATTRIBUTE_KEY, "email");
        parameters.put(EmailOTPAuthenticatorConstants.EMAIL_API, "EmailAPI");
        authenticatorConfig.setParameterMap(parameters);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);
        authenticatedUser.setUserName(USER_NAME);
        context.setSubject(authenticatedUser);
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        context.setProperty(EmailOTPAuthenticatorConstants.USER_NAME, USER_NAME);
        context.setAuthenticatorProperties(parameters);
        federatedAuthenticatorUtilMock.when(() -> FederatedAuthenticatorUtil.isUserExistInUserStore(anyString()))
                .thenReturn(true);
        identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        fileBasedConfigurationBuilderMock.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        frameworkUtilsMock.when(() -> FrameworkUtils.getQueryStringWithFrameworkContextId(anyString(), anyString(), 
                        anyString())).thenReturn(null);
        setStepConfigWithFederatedAuthenticator(authenticatedUser, authenticatorConfig);
        mockFederatedEmailAttributeKey(parameters, authenticatedUser, EMAIL_ADDRESS);
        AuthenticatorFlowStatus status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test
    public void testGetPrepareURLParams() throws Exception {
        String api = "gmail";
        String urlParams = "send=true";
        Map<String, String> parameters = new HashMap<>();
        parameters.put(api + EmailOTPAuthenticatorConstants.URL_PARAMS, urlParams);
        //get from context
        context.setTenantDomain(TENANT_DOMAIN);
        context.setProperty(api + EmailOTPAuthenticatorConstants.URL_PARAMS, urlParams);
        Assert.assertEquals(EmailOTPAuthenticatorTestHelper.getPrepareURLParams(emailOTPAuthenticator,
                context, parameters, api), urlParams);
        //get from parameters
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        Assert.assertEquals(EmailOTPAuthenticatorTestHelper.getPrepareURLParams(emailOTPAuthenticator,
                context, parameters, api), urlParams);
    }

    @Test
    public void testGetPrepareFormData() throws Exception {
        String api = "gmail";
        String formData = "accessToken=asdf";
        Map<String, String> parameters = new HashMap<>();
        parameters.put(api + EmailOTPAuthenticatorConstants.FORM_DATA, formData);
        //get from context
        context.setTenantDomain(TENANT_DOMAIN);
        context.setProperty(api + EmailOTPAuthenticatorConstants.FORM_DATA, formData);
        Assert.assertEquals(EmailOTPAuthenticatorTestHelper.getPrepareFormData(emailOTPAuthenticator,
                context, parameters, api), formData);
        //get from parameters
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        Assert.assertEquals(EmailOTPAuthenticatorTestHelper.getPrepareFormData(emailOTPAuthenticator,
                context, parameters, api), formData);
    }

    @Test
    public void testGetFailureString() throws Exception {
        String api = "gmail";
        String failureString = "Authentication Failed";
        Map<String, String> parameters = new HashMap<>();
        parameters.put(api + EmailOTPAuthenticatorConstants.FAILURE, failureString);
        //get from context
        context.setTenantDomain(TENANT_DOMAIN);
        context.setProperty(api + EmailOTPAuthenticatorConstants.FAILURE, failureString);
        Assert.assertEquals(EmailOTPAuthenticatorTestHelper.getFailureString(emailOTPAuthenticator,
                context, parameters, api), failureString);
        //get from parameters
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        Assert.assertEquals(EmailOTPAuthenticatorTestHelper.getFailureString(emailOTPAuthenticator,
                context, parameters, api), failureString);
    }

    @Test
    public void testGetAuthTokenType() throws Exception {
        String api = "gmail";
        String tokenType = "Oauth2";
        Map<String, String> parameters = new HashMap<>();
        parameters.put(api + EmailOTPAuthenticatorConstants.HTTP_AUTH_TOKEN_TYPE, tokenType);
        //get from context
        context.setTenantDomain(TENANT_DOMAIN);
        context.setProperty(api + EmailOTPAuthenticatorConstants.HTTP_AUTH_TOKEN_TYPE, tokenType);
        Assert.assertEquals(EmailOTPAuthenticatorTestHelper.getAuthTokenType(emailOTPAuthenticator,
                context, parameters, api), tokenType);
        //get from parameters
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        Assert.assertEquals(EmailOTPAuthenticatorTestHelper.getAuthTokenType(emailOTPAuthenticator,
                context, parameters, api), tokenType);
    }

    @Test
    public void testGetAccessTokenEndpoint() throws Exception {
        String api = "gmail";
        String tokenEndpoint = "api/v4/oauth2/token";
        Map<String, String> parameters = new HashMap<>();
        parameters.put(api + EmailOTPAuthenticatorConstants.EMAILOTP_TOKEN_ENDPOINT, tokenEndpoint);
        //get from context
        context.setTenantDomain(TENANT_DOMAIN);
        context.setProperty(api + EmailOTPAuthenticatorConstants.EMAILOTP_TOKEN_ENDPOINT, tokenEndpoint);
        Assert.assertEquals(EmailOTPAuthenticatorTestHelper.getAccessTokenEndpoint(emailOTPAuthenticator,
                context, parameters, api), tokenEndpoint);
        //get from parameters
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        Assert.assertEquals(EmailOTPAuthenticatorTestHelper.getAccessTokenEndpoint(emailOTPAuthenticator,
                context, parameters, api), tokenEndpoint);
    }

    @Test
    public void testGetAPI() throws Exception {
        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(EmailOTPAuthenticatorConstants.EMAIL_API, "EmailAPI");
        Assert.assertEquals(EmailOTPAuthenticatorTestHelper.getAPI(emailOTPAuthenticator, authenticatorProperties),
                EmailOTPAuthenticatorConstants.EMAIL_API);
    }

    @Test
    public void testIsShowEmailAddressInUIEnable() throws Exception {
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        Map<String, String> parametersMap = new HashMap<>();
        parametersMap.put(EmailOTPAuthenticatorConstants.SHOW_EMAIL_ADDRESS_IN_UI, "true");
        Assert.assertTrue(EmailOTPAuthenticatorTestHelper.isShowEmailAddressInUIEnable(emailOTPAuthenticator,
                context, parametersMap));
    }

    @Test
    public void testIsShowEmailAddressInUIEnableForTenant() throws Exception {
        context.setTenantDomain(TENANT_DOMAIN);
        context.setProperty(EmailOTPAuthenticatorConstants.SHOW_EMAIL_ADDRESS_IN_UI, "false");
        Assert.assertFalse(EmailOTPAuthenticatorTestHelper.isShowEmailAddressInUIEnable(emailOTPAuthenticator,
                context, null));
    }

    @Test
    public void testisEmailAddressUpdateEnable() throws Exception {
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        Map<String, String> parametersMap = new HashMap<>();
        parametersMap.put(EmailOTPAuthenticatorConstants.IS_ENABLE_EMAIL_VALUE_UPDATE, "true");
        Assert.assertTrue(EmailOTPAuthenticatorTestHelper.isEmailAddressUpdateEnable(emailOTPAuthenticator,
                context, parametersMap));
    }

    @Test
    public void testisEmailAddressUpdateEnableForTenant() throws Exception {
        context.setTenantDomain(TENANT_DOMAIN);
        context.setProperty(EmailOTPAuthenticatorConstants.IS_ENABLE_EMAIL_VALUE_UPDATE, "false");
        Assert.assertFalse(EmailOTPAuthenticatorTestHelper.isEmailAddressUpdateEnable(emailOTPAuthenticator,
                context, null));
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testUpdateUserAttributeWithNullUserRealm() throws Throwable {
        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantDomain(anyString()))
                .thenReturn(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                .thenReturn(EmailOTPAuthenticatorTestConstants.TENANT_ID);
        identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(null);
        EmailOTPAuthenticatorTestHelper.updateUserAttribute(emailOTPAuthenticator, USER_NAME, new HashMap<>(),
                TENANT_DOMAIN);
    }

    @Test(expectedExceptions = {AuthenticationFailedException.class})
    public void testUpdateUserAttributeWithUserStoreException() throws Throwable {
        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantDomain(anyString()))
                .thenReturn(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(anyString()))
                .thenReturn(EmailOTPAuthenticatorTestConstants.TENANT_ID);
        identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        EmailOTPAuthenticatorTestHelper.updateUserAttribute(emailOTPAuthenticator, USER_NAME, new HashMap<>(),
                TENANT_DOMAIN);
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testCheckEmailOTPBehaviour() throws Throwable {
        String api = "gmail";
        String mailingEndpoint = "api/v1/sendMail";
        Map<String, String> emailOTPParameters = new HashMap<>();
        Map<String, String> authenticatorProperties = new HashMap<>();
        emailOTPParameters.put(api + EmailOTPAuthenticatorConstants.MAILING_ENDPOINT, mailingEndpoint);
        emailOTPParameters.put(api + EmailOTPAuthenticatorConstants.EMAILOTP_API_KEY, "apiKey");
        emailOTPParameters.put(api + EmailOTPAuthenticatorConstants.REFRESH_TOKEN, "refreshToken");
        emailOTPParameters.put(api + EmailOTPAuthenticatorConstants.CLIENT_ID, "clientId");
        emailOTPParameters.put(api + EmailOTPAuthenticatorConstants.CLIENT_SECRET, "clientSecret");
        authenticatorProperties.put(EmailOTPAuthenticatorConstants.EMAIL_API, api);
        authenticatorProperties.put(EmailOTPAuthenticatorConstants.EMAILOTP_EMAIL,
                EMAIL_ADDRESS);
        context.setTenantDomain(EmailOTPAuthenticatorConstants.SUPER_TENANT);
        EmailOTPAuthenticatorTestHelper.checkEmailOTPBehaviour(emailOTPAuthenticator, context,
                emailOTPParameters, authenticatorProperties, EMAIL_ADDRESS,
                USER_NAME, "123456", EmailOTPAuthenticatorConstants.IP_ADDRESS);
    }

    /**
     * Mock the federated attribute key.
     *
     * @param parameters        paramters map.
     * @param authenticatedUser authenticated user.
     * @param emailAddress      email address of the user.
     */
    private void mockFederatedEmailAttributeKey(Map<String, String> parameters, AuthenticatedUser authenticatedUser,
                                                String emailAddress) {
        Map<ClaimMapping, String> userClaims = new HashMap<>();
        userClaims.put(ClaimMapping.build("email", null, null, false),
                emailAddress);
        authenticatedUser.setUserAttributes(userClaims);

        Map<String, AuthenticatedIdPData> authenticatedIdPs = new HashMap<>();

        AuthenticatedIdPData authenticatedIdPData = new AuthenticatedIdPData();
        authenticatedIdPData.setUser(authUser);
        when(authUser.getUserAttributes()).thenReturn(userClaims);

        when(context.getCurrentAuthenticatedIdPs()).thenReturn(authenticatedIdPs);
        federatedAuthenticatorUtilMock.when(() -> FederatedAuthenticatorUtil
                        .getAuthenticatorConfig(EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME))
                .thenReturn(parameters);
    }

    /**
     * Set a step configuration to the context with local authenticator and email OTP authenticator.
     *
     * @param authenticatedUser   {@link AuthenticatedUser} object
     * @param authenticatorConfig {@link AuthenticatorConfig} object
     */
    private void setStepConfigWithBasicAuthenticator(AuthenticatedUser authenticatedUser,
                                                     AuthenticatorConfig authenticatorConfig) {

        Map<Integer, StepConfig> stepConfigMap = new HashMap<>();
        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatedUser(authenticatedUser);
        stepConfig.setSubjectAttributeStep(true);
        stepConfig.setAuthenticatedIdP("LOCAL");
        AuthenticatorConfig localAuthenticatorConfig = new AuthenticatorConfig();
        localAuthenticatorConfig.setName("BasicAuthenticator");
        when(localApplicationAuthenticator.getName()).thenReturn("BasicAuthenticator");
        localAuthenticatorConfig.setApplicationAuthenticator(localApplicationAuthenticator);
        stepConfig.setAuthenticatedAutenticator(localAuthenticatorConfig);
        stepConfigMap.put(1, stepConfig);

        // Email OTP authenticator step
        StepConfig emailOTPStep = new StepConfig();
        authenticatorConfig.setName(EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        List<AuthenticatorConfig> authenticatorList = new ArrayList<>();
        authenticatorList.add(authenticatorConfig);
        emailOTPStep.setAuthenticatorList(authenticatorList);
        stepConfigMap.put(2, emailOTPStep);

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setSaasApp(false);
        ApplicationConfig applicationConfig = new ApplicationConfig(serviceProvider,
                EmailOTPAuthenticatorConstants.SUPER_TENANT);

        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepConfigMap);
        sequenceConfig.setApplicationConfig(applicationConfig);
        context.setSequenceConfig(sequenceConfig);
        context.setCurrentStep(2);
    }

    /**
     * Set a step configuration to the context with federated authenticator and email OTP authenticator.
     *
     * @param authenticatedUser   {@link AuthenticatedUser} object
     * @param authenticatorConfig {@link AuthenticatorConfig} object
     */
    private void setStepConfigWithFederatedAuthenticator(AuthenticatedUser authenticatedUser,
                                                         AuthenticatorConfig authenticatorConfig) {

        Map<Integer, StepConfig> stepConfigMap = new HashMap<>();
        StepConfig stepConfig = new StepConfig();
        stepConfig.setSubjectAttributeStep(true);
        Map<ClaimMapping, String> userClaims = new HashMap<>();
        userClaims.put(ClaimMapping.build("email", null, null, false),
                EMAIL_ADDRESS);
        authenticatedUser.setUserAttributes(userClaims);
        authenticatedUser.setFederatedUser(true);
        stepConfig.setAuthenticatedUser(authenticatedUser);
        stepConfig.setAuthenticatedIdP("FEDERATED");
        AuthenticatorConfig federatedAuthenticatorConfig = new AuthenticatorConfig();
        stepConfig.setAuthenticatedAutenticator(federatedAuthenticatorConfig);
        stepConfigMap.put(1, stepConfig);

        // Email OTP authenticator step
        StepConfig emailOTPStep = new StepConfig();
        authenticatorConfig.setName(EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        List<AuthenticatorConfig> authenticatorList = new ArrayList<>();
        authenticatorList.add(authenticatorConfig);
        emailOTPStep.setAuthenticatorList(authenticatorList);
        stepConfigMap.put(2, emailOTPStep);

        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepConfigMap);
        context.setSequenceConfig(sequenceConfig);
        context.setCurrentStep(2);
    }

    @Test
    public void testProcessAuthenticationResponseWithValidBackupCode() throws Exception {

        when(httpServletRequest.getParameter(EmailOTPAuthenticatorConstants.CODE)).thenReturn("123456");
        context.setProperty(EmailOTPAuthenticatorConstants.OTP_TOKEN, "123");
        context.setProperty(EmailOTPAuthenticatorConstants.USER_NAME, USER_NAME);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);
        authenticatedUser.setUserName(USER_NAME);
        setStepConfigWithBasicAuthenticator(authenticatedUser, authenticatorConfig);
        when((AuthenticatedUser) context.getProperty(EmailOTPAuthenticatorConstants.AUTHENTICATED_USER)).
                thenReturn(authenticatedUser);
        emailOTPUtilsMock.when(() -> EmailOTPUtils.getConfiguration(context,
                EmailOTPAuthenticatorConstants.BACKUP_CODE)).thenReturn("true");
        when(context.getProperty(EmailOTPAuthenticatorConstants.OTP_GENERATED_TIME)).thenReturn(anyLong());
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        mockUserRealm();
        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantAwareUsername(USER_NAME))
                .thenReturn(USER_NAME);
        when(userStoreManager.getUserClaimValues(anyString(),
                eq(new String[]{EmailOTPAuthenticatorConstants.OTP_BACKUP_CODES_CLAIM}), nullable(String.class)))
                .thenReturn(Collections.singletonMap(EmailOTPAuthenticatorConstants.OTP_BACKUP_CODES_CLAIM,
                        "123456,789123"));
        when(userStoreManager.getClaimManager()).thenReturn(
                (org.wso2.carbon.user.core.claim.ClaimManager) claimManager);
        when(userStoreManager.getClaimManager().getClaim(EmailOTPAuthenticatorConstants.OTP_BACKUP_CODES_CLAIM))
                .thenReturn(claim);
        when(context.getProperty(EmailOTPAuthenticatorConstants.CODE_MISMATCH)).thenReturn(false);
        EmailOTPAuthenticatorTestHelper.processAuthenticationResponse(emailOTPAuthenticator,
                httpServletRequest, httpServletResponse, context);
    }

    @Test
    public void testProcessAuthenticationResponseWithValidBackupCodeInIdentityClaim() throws Exception {

        when(httpServletRequest.getParameter(EmailOTPAuthenticatorConstants.CODE)).thenReturn("123456");
        context.setProperty(EmailOTPAuthenticatorConstants.OTP_TOKEN, "123");
        context.setProperty(EmailOTPAuthenticatorConstants.USER_NAME, USER_NAME);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);
        authenticatedUser.setUserName(USER_NAME);
        setStepConfigWithBasicAuthenticator(authenticatedUser, authenticatorConfig);
        when((AuthenticatedUser) context.getProperty(EmailOTPAuthenticatorConstants.AUTHENTICATED_USER)).
                thenReturn(authenticatedUser);
        emailOTPUtilsMock.when(() -> EmailOTPUtils
                .getConfiguration(context, EmailOTPAuthenticatorConstants.BACKUP_CODE)).thenReturn("true");
        when(context.getProperty(EmailOTPAuthenticatorConstants.OTP_GENERATED_TIME)).thenReturn(anyLong());
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        mockUserRealm();
        multitenantUtilsMock.when(() -> MultitenantUtils.getTenantAwareUsername(USER_NAME)).thenReturn(USER_NAME);
        identityUtilMock.when(() -> IdentityUtil
                        .getProperty(EmailOTPAuthenticatorConstants.HANDLE_BACKUP_CODES_AS_IDENTITY_CLAIM))
                .thenReturn("true");
        when(userStoreManager.getUserClaimValues(anyString(),
                eq(new String[]{EmailOTPAuthenticatorConstants.OTP_BACKUP_CODES_IDENTITY_CLAIM}), nullable(String.class)))
                .thenReturn(Collections.singletonMap(EmailOTPAuthenticatorConstants.OTP_BACKUP_CODES_IDENTITY_CLAIM,
                        "123456,789123"));
        when(userStoreManager.getClaimManager()).thenReturn(claimManager);
        when(userStoreManager.getClaimManager().getClaim(EmailOTPAuthenticatorConstants.OTP_BACKUP_CODES_CLAIM))
                .thenReturn(claim);
        when(context.getProperty(EmailOTPAuthenticatorConstants.CODE_MISMATCH)).thenReturn(false);
        EmailOTPAuthenticatorTestHelper.processAuthenticationResponse(emailOTPAuthenticator,
                httpServletRequest, httpServletResponse, context);
    }

    private void mockServiceURLBuilder() throws URLBuilderException {

        ServiceURLBuilder builder = new ServiceURLBuilder() {

            String path = "";

            @Override
            public ServiceURLBuilder addPath(String... strings) {

                Arrays.stream(strings).forEach(x -> {
                    path += "/" + x;
                });
                return this;
            }

            @Override
            public ServiceURLBuilder addParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURLBuilder setFragment(String s) {

                return this;
            }

            @Override
            public ServiceURLBuilder addFragmentParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURL build() throws URLBuilderException {

                ServiceURL serviceURL = mock(ServiceURL.class);
                when(serviceURL.getAbsolutePublicURL()).thenReturn("https://localhost:9443" + path);
                when(serviceURL.getRelativePublicURL()).thenReturn(path);
                when(serviceURL.getRelativeInternalURL()).thenReturn(path);
                return serviceURL;
            }
        };

        serviceURLBuilderMock.when(ServiceURLBuilder::create).thenReturn(builder);
    }

    /**
     * Set a step configuration to the context with EmailOTP authenticator.
     *
     * @param authenticatorConfig object
     * @param context             object
     */
    private void setStepConfigWithEmailOTPAuthenticator(AuthenticatorConfig authenticatorConfig, AuthenticationContext context) {

        Map<Integer, StepConfig> stepConfigMap = new HashMap<>();
        // Email OTP authenticator step.
        StepConfig emailOTPStep = new StepConfig();
        authenticatorConfig.setName(EmailOTPAuthenticatorConstants.AUTHENTICATOR_NAME);
        List<AuthenticatorConfig> authenticatorList = new ArrayList<>();
        authenticatorList.add(authenticatorConfig);
        emailOTPStep.setAuthenticatorList(authenticatorList);
        emailOTPStep.setSubjectAttributeStep(true);
        stepConfigMap.put(1, emailOTPStep);

        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepConfigMap);
        context.setSequenceConfig(sequenceConfig);
        context.setCurrentStep(1);
    }

    @Test(description = "Test case for processValidUserToken() method")
    public void testProcessValidUserToken() throws Exception {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(USER_NAME);
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);
        context.setProperty(EmailOTPAuthenticatorConstants.OTP_TOKEN, "123456");
        context.setProperty(EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN, "access-token");

        EmailOTPAuthenticatorTestHelper.processValidUserToken(emailOTPAuthenticator, context, authenticatedUser);

        Assert.assertEquals(context.getProperty(EmailOTPAuthenticatorConstants.OTP_TOKEN), "");
        Assert.assertEquals(context.getProperty(EmailOTPAuthenticatorConstants.EMAILOTP_ACCESS_TOKEN), "");
        Assert.assertEquals(context.getSubject(), authenticatedUser);
    }

    @Test(description = "Test case for isBackUpCodeValid() method with valid backup code")
    public void testIsBackUpCodeValidWithValidCode() throws Exception {

        String[] savedOTPs = {"code1", "code2", "code3"};
        String userToken = "code2";

        boolean result = EmailOTPAuthenticatorTestHelper.isBackUpCodeValid(emailOTPAuthenticator, savedOTPs, userToken);

        Assert.assertTrue(result);
    }

    @Test(description = "Test case for isBackUpCodeValid() method with invalid backup code")
    public void testIsBackUpCodeValidWithInvalidCode() throws Exception {

        String[] savedOTPs = {"code1", "code2", "code3"};
        String userToken = "invalidCode";

        boolean result = EmailOTPAuthenticatorTestHelper.isBackUpCodeValid(emailOTPAuthenticator, savedOTPs, userToken);

        Assert.assertFalse(result);
    }

    @Test(description = "Test case for isBackUpCodeValid() method with empty backup codes")
    public void testIsBackUpCodeValidWithEmptyBackupCodes() throws Exception {

        String[] savedOTPs = {};
        String userToken = "code1";

        boolean result = EmailOTPAuthenticatorTestHelper.isBackUpCodeValid(emailOTPAuthenticator, savedOTPs, userToken);

        Assert.assertFalse(result);
    }

    @Test(description = "Test case for isBackupCodeEnabled() method when backup code is enabled")
    public void testIsBackupCodeEnabledWhenEnabled() throws Exception {

        Map<String, String> parameters = new HashMap<>();
        parameters.put(EmailOTPAuthenticatorConstants.BACKUP_CODE, "true");
        context.setAuthenticatorProperties(parameters);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(USER_NAME);
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);

        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatedUser(authenticatedUser);
        stepConfig.setSubjectAttributeStep(true);
        stepConfig.setAuthenticatedIdP("LOCAL");
        Map<Integer, StepConfig> stepConfigMap = new HashMap<>();
        stepConfigMap.put(1, stepConfig);

        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepConfigMap);
        context.setSequenceConfig(sequenceConfig);

        emailOTPUtilsMock.when(() -> EmailOTPUtils
                        .getConfiguration(context, EmailOTPAuthenticatorConstants.BACKUP_CODE)).thenReturn("true");

        boolean result = EmailOTPAuthenticatorTestHelper.isBackupCodeEnabled(emailOTPAuthenticator, context);

        Assert.assertTrue(result);
    }

    @Test(description = "Test case for isBackupCodeEnabled() method when backup code is disabled")
    public void testIsBackupCodeEnabledWhenDisabled() throws Exception {

        Map<String, String> parameters = new HashMap<>();
        parameters.put(EmailOTPAuthenticatorConstants.BACKUP_CODE, "false");
        context.setAuthenticatorProperties(parameters);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(USER_NAME);
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);

        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatedUser(authenticatedUser);
        stepConfig.setSubjectAttributeStep(true);
        stepConfig.setAuthenticatedIdP("LOCAL");
        Map<Integer, StepConfig> stepConfigMap = new HashMap<>();
        stepConfigMap.put(1, stepConfig);

        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepConfigMap);
        context.setSequenceConfig(sequenceConfig);

        emailOTPUtilsMock.when(() -> EmailOTPUtils
                        .getConfiguration(context, EmailOTPAuthenticatorConstants.BACKUP_CODE)).thenReturn("false");

        boolean result = EmailOTPAuthenticatorTestHelper.isBackupCodeEnabled(emailOTPAuthenticator, context);

        Assert.assertFalse(result);
    }

    @Test(description = "Test case for getAuthenticatedUser() method")
    public void testGetAuthenticatedUser() throws Exception {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(USER_NAME);
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);

        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatedUser(authenticatedUser);
        stepConfig.setSubjectAttributeStep(true);
        Map<Integer, StepConfig> stepConfigMap = new HashMap<>();
        stepConfigMap.put(1, stepConfig);

        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepConfigMap);
        context.setSequenceConfig(sequenceConfig);

        AuthenticatedUser result = EmailOTPAuthenticatorTestHelper.getAuthenticatedUser(emailOTPAuthenticator, context);

        Assert.assertNotNull(result);
        Assert.assertEquals(result.getUserName(), USER_NAME);
    }

    @Test(description = "Test case for getAuthenticatedUser() method with last authenticated user")
    public void testGetAuthenticatedUserWithLastAuthenticatedUser() throws Exception {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(USER_NAME);
        authenticatedUser.setAuthenticatedSubjectIdentifier(USER_NAME);

        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatedUser(authenticatedUser);
        stepConfig.setSubjectAttributeStep(true);
        Map<Integer, StepConfig> stepConfigMap = new HashMap<>();
        stepConfigMap.put(1, stepConfig);

        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepConfigMap);
        context.setSequenceConfig(sequenceConfig);

        AuthenticatedUser result = EmailOTPAuthenticatorTestHelper.getAuthenticatedUser(emailOTPAuthenticator, context);

        Assert.assertNotNull(result);
        Assert.assertEquals(result.getUserName(), USER_NAME);
    }

    @Test(description = "Test case for verifyUserExists() method when user exists")
    public void testVerifyUserExistsWhenUserExists() throws Throwable {

        String username = USER_NAME;
        String tenantDomain = TENANT_DOMAIN;

        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(tenantDomain)).thenReturn(TENANT_ID);
        identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isExistingUser(username)).thenReturn(true);

        // Should not throw exception
        EmailOTPAuthenticatorTestHelper.verifyUserExists(emailOTPAuthenticator, username, tenantDomain);
    }

    @Test(description = "Test case for verifyUserExists() method when user does not exist",
            expectedExceptions = AuthenticationFailedException.class)
    public void testVerifyUserExistsWhenUserDoesNotExist() throws Throwable {

        String username = USER_NAME;
        String tenantDomain = TENANT_DOMAIN;

        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(tenantDomain)).thenReturn(TENANT_ID);
        identityTenantUtilMock.when(IdentityTenantUtil::getRealmService).thenReturn(realmService);
        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.isExistingUser(username)).thenReturn(false);

        EmailOTPAuthenticatorTestHelper.verifyUserExists(emailOTPAuthenticator, username, tenantDomain);
    }

    @Test(description = "Test case for getRedirectURL() method with query params")
    public void testGetRedirectURLWithQueryParams() throws Exception {

        String baseURI = "https://localhost:9443/emailotpauthenticationendpoint/emailotp.jsp";
        String queryParams = "sessionDataKey=12345&authenticators=EmailOTP";

        String result = EmailOTPAuthenticatorTestHelper.getRedirectURL(emailOTPAuthenticator, baseURI, queryParams);

        Assert.assertTrue(result.contains(baseURI));
        Assert.assertTrue(result.contains(queryParams));
        Assert.assertTrue(result.contains("&authenticators=EmailOTP"));
    }

    @Test(description = "Test case for getRedirectURL() method without query params")
    public void testGetRedirectURLWithoutQueryParams() throws Exception {

        String baseURI = "https://localhost:9443/emailotpauthenticationendpoint/emailotp.jsp";
        String queryParams = "";

        String result = EmailOTPAuthenticatorTestHelper.getRedirectURL(emailOTPAuthenticator, baseURI, queryParams);

        Assert.assertTrue(result.contains(baseURI));
        Assert.assertTrue(result.contains("?authenticators=EmailOTP"));
    }

    @Test(description = "Test case for getEmailOTPLength() method with default value")
    public void testGetEmailOTPLengthWithDefaultValue() throws Exception {

        Map<String, String> authenticatorProperties = new HashMap<>();

        int result = EmailOTPAuthenticatorTestHelper.getEmailOTPLength(emailOTPAuthenticator, authenticatorProperties);

        Assert.assertEquals(result, EmailOTPAuthenticatorConstants.NUMBER_DIGIT);
    }

    @Test(description = "Test case for getEmailOTPLength() method with custom value")
    public void testGetEmailOTPLengthWithCustomValue() throws Exception {

        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(EmailOTPAuthenticatorConstants.EMAIL_OTP_LENGTH, "8");

        int result = EmailOTPAuthenticatorTestHelper.getEmailOTPLength(emailOTPAuthenticator, authenticatorProperties);

        Assert.assertEquals(result, 8);
    }

    @Test(description = "Test case for getEmailOTPLength() method with invalid value")
    public void testGetEmailOTPLengthWithInvalidValue() throws Exception {

        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(EmailOTPAuthenticatorConstants.EMAIL_OTP_LENGTH, "20");

        int result = EmailOTPAuthenticatorTestHelper.getEmailOTPLength(emailOTPAuthenticator, authenticatorProperties);

        // Should return default value when out of range
        Assert.assertEquals(result, EmailOTPAuthenticatorConstants.NUMBER_DIGIT);
    }

    @Test(description = "Test case for getEmailOTPExpiryTime() method with default value")
    public void testGetEmailOTPExpiryTimeWithDefaultValue() throws Exception {

        Map<String, String> authenticatorProperties = new HashMap<>();

        int result = EmailOTPAuthenticatorTestHelper.getEmailOTPExpiryTime(emailOTPAuthenticator, authenticatorProperties);

        Assert.assertEquals(result, Integer.parseInt(EmailOTPAuthenticatorConstants.OTP_EXPIRE_TIME_DEFAULT));
    }

    @Test(description = "Test case for getEmailOTPExpiryTime() method with custom value")
    public void testGetEmailOTPExpiryTimeWithCustomValue() throws Exception {

        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(EmailOTPAuthenticatorConstants.EMAIL_OTP_EXPIRY_TIME, "10");

        int result = EmailOTPAuthenticatorTestHelper.getEmailOTPExpiryTime(emailOTPAuthenticator, authenticatorProperties);

        Assert.assertEquals(result, 10 * 60 * 1000);
    }

    @Test(description = "Test case for getMultiOptionURIQueryParam() method with multiOptionURI")
    public void testGetMultiOptionURIQueryParamWithValue() throws Exception {

        when(httpServletRequest.getParameter(EmailOTPAuthenticatorConstants.MULTI_OPTION_URI))
                .thenReturn("https://localhost:9443/commonauth");

        String result = EmailOTPAuthenticatorTestHelper.getMultiOptionURIQueryParam(emailOTPAuthenticator,
                httpServletRequest);

        Assert.assertTrue(result.contains("&multiOptionURI="));
        Assert.assertTrue(result.contains("https"));
    }

    @Test(description = "Test case for getMultiOptionURIQueryParam() method without multiOptionURI")
    public void testGetMultiOptionURIQueryParamWithoutValue() throws Exception {

        when(httpServletRequest.getParameter(EmailOTPAuthenticatorConstants.MULTI_OPTION_URI))
                .thenReturn(null);

        String result = EmailOTPAuthenticatorTestHelper.getMultiOptionURIQueryParam(emailOTPAuthenticator,
                httpServletRequest);

        Assert.assertEquals(result, "");
    }

    @Test(description = "Test case for getMultiOptionURIQueryParam() method with null request")
    public void testGetMultiOptionURIQueryParamWithNullRequest() throws Exception {

        String result = EmailOTPAuthenticatorTestHelper.getMultiOptionURIQueryParam(emailOTPAuthenticator,
                (HttpServletRequest) null);

        Assert.assertEquals(result, "");
    }
}
