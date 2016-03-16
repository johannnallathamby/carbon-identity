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

package org.wso2.carbon.identity.application.authentication.framework.inbound;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuthenticatedRequest extends InboundAuthenticationRequest {

    private static final long serialVersionUID = 3359421085612381634L;

    private String sessionDataKey;

    protected AuthenticatedRequest(AuthenticatedRequestBuilder builder) {
        super(builder);
        this.sessionDataKey = builder.sessionDataKey;
    }

    public static class AuthenticatedRequestBuilder extends InboundAuthenticationRequestBuilder {

        private String sessionDataKey;

        public AuthenticatedRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public AuthenticatedRequestBuilder setSessionDataKey(String sessionDataKey) {
            this.sessionDataKey = sessionDataKey;
            return this;
        }

        @Override
        public AuthenticatedRequest build() throws AuthenticationFrameworkRuntimeException {
            return new AuthenticatedRequest(this);
        }
    }
}
