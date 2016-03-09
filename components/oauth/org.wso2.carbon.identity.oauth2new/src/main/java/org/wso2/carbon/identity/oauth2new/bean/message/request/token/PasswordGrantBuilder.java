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

package org.wso2.carbon.identity.oauth2new.bean.message.request.token;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.application.authentication.framework.inbound.AuthenticationFrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundAuthenticationRequest;
import org.wso2.carbon.identity.oauth2new.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PasswordGrantBuilder extends TokenRequestBuilder {

    String username;
    char[] password;

    public PasswordGrantBuilder(HttpServletRequest request, HttpServletResponse response) {
        super(request, response);
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) throws AuthenticationFrameworkRuntimeException {
        if(StringUtils.equals(GrantType.PASSWORD.toString(), request.getParameter(OAuth.OAUTH_GRANT_TYPE))) {
            return true;
        }
        return false;
    }

    @Override
    public InboundAuthenticationRequest build() throws AuthenticationFrameworkRuntimeException {

        this.grantType = request.getParameter(OAuth.OAUTH_GRANT_TYPE);
        this.requestedScopes = OAuth2Util.buildScopeSet(request.getParameter(OAuth.OAUTH_SCOPE));
        this.username = request.getParameter(OAuth.OAUTH_USERNAME);
        this.password = request.getParameter(OAuth.OAUTH_PASSWORD).toCharArray();
        return new PasswordGrantRequest(this);
    }
}
