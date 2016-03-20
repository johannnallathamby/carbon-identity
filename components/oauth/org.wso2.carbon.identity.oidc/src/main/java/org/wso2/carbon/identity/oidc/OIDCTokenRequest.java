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

package org.wso2.carbon.identity.oidc;

import org.wso2.carbon.identity.application.authentication.framework.inbound.AuthenticationFrameworkRuntimeException;
import org.wso2.carbon.identity.oauth2new.bean.message.request.token.OAuth2TokenRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OIDCTokenRequest extends OAuth2TokenRequest {

    private static final long serialVersionUID = -3009563708954787261L;

    protected OIDCTokenRequest(OIDCTokenRequestBuilder builder) {
        super(builder);
    }

    public static class OIDCTokenRequestBuilder extends TokenRequestBuilder {

        public OIDCTokenRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public OIDCTokenRequestBuilder setGrantType(String grantType) {
            return this;
        }

        public OIDCTokenRequest build() throws AuthenticationFrameworkRuntimeException {
            return new OIDCTokenRequest(this);
        }

    }
}
