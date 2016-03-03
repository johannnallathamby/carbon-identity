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
import java.util.HashMap;
import java.util.Map;

public abstract class InboundAuthenticationRequestBuilder {

    protected HttpServletRequest request;
    protected HttpServletResponse response;
    Map<String, String> headers = new HashMap<String, String>();
    Map<String, Cookie> cookies = new HashMap<String, Cookie>();
    Map<String, String[]> parameters = new HashMap<String, String[]>();

    public InboundAuthenticationRequestBuilder (HttpServletRequest request, HttpServletResponse response) {
        this.request = request;
        this.response = response;
    }

    public InboundAuthenticationRequestBuilder setHeaders(Map<String, String> headers) {
        this.headers = headers;
        return this;
    }

    public InboundAuthenticationRequestBuilder addResponseHeader(String key, String values) {
        headers.put(key, values);
        return this;
    }

    public InboundAuthenticationRequestBuilder setCookies(Map<String, Cookie> cookies) {
        this.cookies = cookies;
        return this;
    }

    public InboundAuthenticationRequestBuilder addCookie(String key, Cookie values) {
        cookies.put(key, values);
        return this;
    }

    public InboundAuthenticationRequestBuilder setParameters(Map<String, String[]> parameters) {
        this.parameters = parameters;
        return this;
    }

	public abstract String getName();

	public abstract int getPriority();

	public abstract boolean canHandle(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationFrameworkRuntimeException;

	public abstract InboundAuthenticationRequest build(InboundAuthenticationRequestBuilder builder)
            throws AuthenticationFrameworkRuntimeException ;

}
