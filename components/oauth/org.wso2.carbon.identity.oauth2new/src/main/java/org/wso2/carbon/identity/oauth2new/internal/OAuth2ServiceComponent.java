/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2new.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.oauth2new.OAuth2Service;
import org.wso2.carbon.identity.oauth2new.OAuth2ServiceImpl;
import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2InboundRequestBuilder;
import org.wso2.carbon.identity.oauth2new.dao.OAuth2DAOHandler;
import org.wso2.carbon.identity.oauth2new.handler.client.ClientAuthHandler;
import org.wso2.carbon.identity.oauth2new.handler.issuer.AccessTokenResponseIssuer;
import org.wso2.carbon.identity.oauth2new.handler.persist.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2new.model.OAuth2ServerConfig;
import org.wso2.carbon.identity.oauth2new.processor.OAuth2InboundRequestProcessor;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="identity.oauth2.component" immediate="true"
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService"
 * cardinality="1..1" policy="dynamic" bind="setRegistryService"
 * unbind="unsetRegistryService"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService" cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 * @scr.reference name="identityCoreInitializedEventService"
 * interface="org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent" cardinality="1..1"
 * policy="dynamic" bind="setIdentityCoreInitializedEventService" unbind="unsetIdentityCoreInitializedEventService"
 * @scr.reference name="oauth2.inbound.request.builder"
 * interface="org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2InboundRequestBuilder"
 * cardinality="0..n"
 * policy="dynamic" bind="addOAuth2InboundRequestBuilder" unbind="removeOAuth2InboundRequestBuilder"
 * @scr.reference name="oauth2.inbound.request.processor"
 * interface="org.wso2.carbon.identity.oauth2new.processor.OAuth2InboundRequestProcessor" cardinality="0..n"
 * policy="dynamic" bind="addOAuth2InboundRequestProcessor" unbind="removeOAuth2InboundRequestProcessor"
 * @scr.reference name="oauth2.handler.client.auth"
 * interface="org.wso2.carbon.identity.oauth2new.handler.client.ClientAuthHandler" cardinality="0..n"
 * policy="dynamic" bind="addClientAuthHandler" unbind="removeClientAuthHandler"
 * @scr.reference name="oauth2.handler.issuer.token"
 * interface="org.wso2.carbon.identity.oauth2new.handler.issuer.AccessTokenResponseIssuer" cardinality="0..n"
 * policy="dynamic" bind="addAccessTokenResponseIssuer" unbind="removeAccessTokenResponseIssuer"
 * @scr.reference name="oauth2.handler.persist.token"
 * interface="org.wso2.carbon.identity.oauth2new.handler.persist.TokenPersistenceProcessor" cardinality="0..n"
 * policy="dynamic" bind="addTokenPersistenceProcessor" unbind="removeTokenPersistenceProcessor"
 * @scr.reference name="oauth2.handler.dao"
 * interface="org.wso2.carbon.identity.oauth2new.dao.OAuth2DAO" cardinality="0..n"
 * policy="dynamic" bind="addOAuth2DAOHandler" unbind="removeOAuth2DAOHandler"
 *
 */
public class OAuth2ServiceComponent {

    private static Log log = LogFactory.getLog(OAuth2ServiceComponent.class);
    private BundleContext bundleContext = null;
    private ServiceRegistration oauth2ServiceReg = null;

    protected void activate(ComponentContext context) {

        try {
            OAuth2ServerConfig.getInstance();
            bundleContext = context.getBundleContext();
            oauth2ServiceReg = bundleContext.registerService(OAuth2Service.class.getName(),
                    OAuth2ServiceImpl.getInstance(), null);
            if (log.isDebugEnabled()) {
                log.debug("OAuth2Service is registered");
            }
            if (log.isDebugEnabled()) {
                log.debug("OAuth2 bundle is activated");
            }
        } catch (Throwable e) {
            log.fatal("Error occurred while activating OAuth2 bundle");
        }
    }

    protected void deactivate(ComponentContext context) {

        if(oauth2ServiceReg != null) {
            oauth2ServiceReg.unregister();
        }
        if (log.isDebugEnabled()) {
            log.debug("OAuth2 service is unregistered");
        }
        if (log.isDebugEnabled()) {
            log.debug("OAuth2 bundle is deactivated");
        }
    }

    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the RealmService");
        }
        OAuth2ServiceComponentHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the RealmService");
        }
        OAuth2ServiceComponentHolder.getInstance().setRealmService(null);
    }

    protected void setRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the RegistryService");
        }
        OAuth2ServiceComponentHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the RegistryService");
        }
        OAuth2ServiceComponentHolder.getInstance().setRegistryService(null);
    }

    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the IdentityCoreInitializedEventService");
        }
        OAuth2ServiceComponentHolder.getInstance().setIdentityCoreInitializedEvent(identityCoreInitializedEvent);
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the IdentityCoreInitializedEventService");
        }
        OAuth2ServiceComponentHolder.getInstance().setIdentityCoreInitializedEvent(null);
    }

    protected void addOAuth2InboundRequestBuilder(OAuth2InboundRequestBuilder builder) {
        if (log.isDebugEnabled()) {
            log.debug("Adding OAuth2InboundRequestBuilder " + builder.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getBuilders().add(builder);
    }

    protected void removeOAuth2InboundRequestBuilder(OAuth2InboundRequestBuilder builder) {
        if (log.isDebugEnabled()) {
            log.debug("Removing OAuth2InboundRequestBuilder " + builder.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getBuilders().remove(builder);
    }

    protected void addOAuth2InboundRequestProcessor(OAuth2InboundRequestProcessor processor) {
        if (log.isDebugEnabled()) {
            log.debug("Adding OAuth2InboundRequestProcessor " + processor.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getProcessors().add(processor);
    }

    protected void removeOAuth2InboundRequestProcessor(OAuth2InboundRequestProcessor processor) {
        if (log.isDebugEnabled()) {
            log.debug("Removing OAuth2InboundRequestProcessor " + processor.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getProcessors().remove(processor);
    }

    protected void addClientAuthHandler(ClientAuthHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding ClientAuthHandler " + handler.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getClientAuthHandlers().add(handler);
    }

    protected void removeClientAuthHandler(ClientAuthHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing ClientAuthHandler " + handler.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getClientAuthHandlers().remove(handler);
    }

    protected void addAccessTokenResponseIssuer(AccessTokenResponseIssuer handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding AccessTokenResponseIssuer " + handler.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getAccessTokenIssuers().add(handler);
    }

    protected void removeAccessTokenResponseIssuer(AccessTokenResponseIssuer handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing AccessTokenResponseIssuer " + handler.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getAccessTokenIssuers().remove(handler);
    }

    protected void addTokenPersistenceProcessor(TokenPersistenceProcessor persistenceProcessor) {
        if (log.isDebugEnabled()) {
            log.debug("Adding AccessTokenResponseIssuer " + persistenceProcessor.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getTokenPersistenceProcessors().add(persistenceProcessor);
    }

    protected void removeTokenPersistenceProcessor(TokenPersistenceProcessor persistenceProcessor) {
        if (log.isDebugEnabled()) {
            log.debug("Removing AccessTokenResponseIssuer " + persistenceProcessor.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getTokenPersistenceProcessors().remove(persistenceProcessor);
    }

    protected void addOAuth2DAOHandler(OAuth2DAOHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Adding AccessTokenResponseIssuer " + handler.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getOAuth2DAOHandlers().add(handler);
    }

    protected void removeOAuth2DAOHandler(OAuth2DAOHandler handler) {
        if (log.isDebugEnabled()) {
            log.debug("Removing AccessTokenResponseIssuer " + handler.getName());
        }
        OAuth2ServiceComponentHolder.getInstance().getOAuth2DAOHandlers().remove(handler);
    }
}
