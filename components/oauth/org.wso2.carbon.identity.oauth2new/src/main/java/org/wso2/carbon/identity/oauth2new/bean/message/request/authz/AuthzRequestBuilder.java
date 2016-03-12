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

import org.apache.commons.lang3.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.inbound.AuthenticationFrameworkRuntimeException;
import org.wso2.carbon.identity.oauth2new.bean.message.request.OAuth2InboundRequestBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuthzRequestBuilder extends OAuth2InboundRequestBuilder {

    String responseType;
    String redirectURI;
    String state;

    public AuthzRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
        super(request, response);
    }

    @Override
    public String getName() {
        return "AuthzRequestBuilder";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) throws AuthenticationFrameworkRuntimeException {
        if(StringUtils.isNotBlank(request.getParameter(OAuth.OAUTH_RESPONSE_TYPE))) {
            return true;
        }
        return false;
    }

    public AuthzRequestBuilder setResponseType(String responseType) {
        this.responseType = responseType;
        return this;
    }

    public AuthzRequestBuilder setRedirectURI(String redirectURI) {
        this.redirectURI = redirectURI;
        return this;
    }

    public AuthzRequestBuilder setState(String state) {
        this.state = state;
        return this;
    }

    public OAuth2AuthzRequest build() throws AuthenticationFrameworkRuntimeException  {
        return new OAuth2AuthzRequest(this);
    }
}
