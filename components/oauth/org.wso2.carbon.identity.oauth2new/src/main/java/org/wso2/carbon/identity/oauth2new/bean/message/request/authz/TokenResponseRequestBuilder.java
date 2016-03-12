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

package org.wso2.carbon.identity.oauth2new.bean.message.request.authz;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.wso2.carbon.identity.application.authentication.framework.inbound.AuthenticationFrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationRequest;
import org.wso2.carbon.identity.oauth2new.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.Set;

public class TokenResponseRequestBuilder extends AuthzRequestBuilder {

    String clientId;
    String redirectURI;
    Set<String> scopes = new HashSet<>();

    public TokenResponseRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
        super(request, response);
    }

    public AuthzRequestBuilder setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public AuthzRequestBuilder setRedirectURI(String redirectURI) {
        this.redirectURI = redirectURI;
        return this;
    }

    public AuthzRequestBuilder setScopes(Set<String> scopes) {
        this.scopes = scopes;
        return this;
    }

    @Override
    public String getName() {
        return "TokenResponseRequestBuilder";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) throws AuthenticationFrameworkRuntimeException {
        if(StringUtils.equals(ResponseType.TOKEN.toString(), request.getParameter(OAuth.OAUTH_RESPONSE_TYPE))) {
            return true;
        } else {
            return false;
        }
    }

    public TokenResponseRequest build()
            throws AuthenticationFrameworkRuntimeException {

        this.setClientId(request.getParameter(OAuth.OAUTH_CLIENT_ID));
        this.setRedirectURI(request.getParameter(OAuth.OAUTH_REDIRECT_URI));
        this.setScopes(OAuth2Util.buildScopeSet(request.getParameter(OAuth.OAUTH_SCOPE)));
        return new TokenResponseRequest(this);
    }
}
