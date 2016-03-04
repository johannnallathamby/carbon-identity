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

package org.wso2.carbon.identity.oauth2new.admin.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.oauth2new.admin.listener.OAuth2UserOperationEventListener;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="identity.oauth2.admin.component" immediate="true"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService" cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class OAuth2AdminServiceComponent {

    private static Log log = LogFactory.getLog(OAuth2AdminServiceComponent.class);
    private OAuth2UserOperationEventListener listener = null;
    private ServiceRegistration serviceRegistration = null;

    protected void activate(ComponentContext context) {

        listener = new OAuth2UserOperationEventListener();
        serviceRegistration = context.getBundleContext().registerService(UserOperationEventListener.class.getName(),
                listener, null);
        if(log.isDebugEnabled()) {
            log.debug("Identity OAuth Event Listener is enabled");
        }

        if (log.isDebugEnabled()) {
            log.debug("OAuth2 Admin bundle is activated");
        }
    }

    protected void deactivate(ComponentContext context) {
        if (serviceRegistration != null) {
            serviceRegistration.unregister();
        }
        if (log.isDebugEnabled()) {
            log.info("OAuth2 Admin bundle is deactivated");
        }
    }


    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.info("Setting the RealmService");
        }
        OAuth2AdminServiceComponentHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.info("Unsetting the RealmService");
        }
        OAuth2AdminServiceComponentHolder.getInstance().setRealmService(null);
    }
}
