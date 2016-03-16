/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authentication.framework.inbound;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Enumeration;
import java.util.Properties;

public class InboundAuthenticationRequestFactory {

    protected Properties properties;

    public void init(Properties properties) throws AuthenticationFrameworkRuntimeException {
        this.properties = properties;
    }

    public String getName() {
        return "InboundAuthenticationRequestBuilder";
    }

    public int getPriority() {
        return 0;
    }

    public boolean canHandle(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationFrameworkRuntimeException {
        return true;
    }

    public InboundAuthenticationRequest create(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationFrameworkRuntimeException {

        InboundAuthenticationRequest.InboundAuthenticationRequestBuilder builder = new InboundAuthenticationRequest
                .InboundAuthenticationRequestBuilder(request, response);
        Enumeration<String> headerNames = request.getHeaderNames();
        while(headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            builder.addHeader(headerName, request.getHeader(headerName));
        }
        builder.setParameters(request.getParameterMap());
        Cookie[] cookies = request.getCookies();
        for(Cookie cookie:cookies){
            builder.addCookie(cookie.getName(), cookie);
        }
        return builder.build();
    }

}
