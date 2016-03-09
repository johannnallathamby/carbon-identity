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

package org.wso2.carbon.identity.oauth2new.bean.context;

import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.oauth2new.bean.message.request.token.OAuth2TokenRequest;

import java.io.Serializable;
import java.util.Map;
import java.util.Set;

/*
 * Message context that holds information about the token request to the token endpoint
 */
public class OAuth2TokenMessageContext<T1 extends Serializable, T2 extends Serializable> extends OAuth2MessageContext {

    private static final long serialVersionUID = -5732604278415475580L;

    private User authzUser;

    private Set<String> approvedScopes;

    private long validityPeriod;

    private String clientId;

    public OAuth2TokenMessageContext(OAuth2TokenRequest request, String tenantDomain,
                                     Map<T1,T2> parameters) {
        super(request, tenantDomain, parameters);
    }

    public Set<String> getApprovedScopes() {
        return approvedScopes;
    }

    public void setApprovedScopes(Set<String> approvedScopes) {
        this.approvedScopes = approvedScopes;
    }

    public long getValidityPeriod() {
        return validityPeriod;
    }

    public void setValidityPeriod(long validityPeriod) {
        this.validityPeriod = validityPeriod;
    }

    public User getAuthzUser() {
        return authzUser;
    }

    public void setAuthzUser(User authzUser) {
        this.authzUser = authzUser;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }


    @Override
    public OAuth2TokenRequest getRequest() {
        return (OAuth2TokenRequest)request;
    }

}
