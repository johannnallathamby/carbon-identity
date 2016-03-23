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

package org.wso2.carbon.identity.oauth2new.bean.message.authz;

import org.apache.commons.lang3.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.oauth2new.bean.message.OAuth2InboundRequestFactory;
import org.wso2.carbon.identity.oauth2new.exception.OAuth2ClientException;
import org.wso2.carbon.identity.oauth2new.util.OAuth2Util;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuthzRequestFactory extends OAuth2InboundRequestFactory {

    @Override
    public String getName() {
        return "AuthzRequestFactory";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) throws FrameworkRuntimeException {
        if(StringUtils.isNotBlank(request.getParameter(OAuth.OAUTH_RESPONSE_TYPE))) {
            return true;
        }
        return false;
    }

    public OAuth2AuthzRequest create(HttpServletRequest request, HttpServletResponse response) throws
            FrameworkRuntimeException, OAuth2ClientException {

        OAuth2AuthzRequest.AuthzRequestBuilder builder = new OAuth2AuthzRequest.AuthzRequestBuilder
                (request, response);
        builder.setTenantDomain(request.getParameter(MultitenantConstants.TENANT_DOMAIN));
        builder.setResponseType(request.getParameter(OAuth.OAUTH_RESPONSE_TYPE));
        builder.setClientId(request.getParameter(OAuth.OAUTH_CLIENT_ID));
        builder.setRedirectURI(request.getParameter(OAuth.OAUTH_REDIRECT_URI));
        builder.setState(request.getParameter(OAuth.OAUTH_STATE));
        builder.setScopes(OAuth2Util.buildScopeSet(request.getParameter(OAuth.OAUTH_SCOPE)));
        return builder.build();
    }
}
