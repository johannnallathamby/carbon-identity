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
    Map<String, String[]> parameters = new HashMap<>();

    public InboundAuthenticationRequestBuilder (HttpServletRequest request, HttpServletResponse response) {
        this.request = request;
        this.response = response;
    }

    public InboundAuthenticationRequestBuilder setResponseHeaders(Map<String, String> responseHeaders) {
        this.headers = responseHeaders;
        return this;
    }

    public InboundAuthenticationRequestBuilder addResponseHeaders(Map<String,String> headers) {
        for(Map.Entry<String,String> header:headers.entrySet()) {
            if(this.headers.containsKey(header.getKey())) {
                throw AuthenticationFrameworkRuntimeException.error("Headers map trying to override existing " +
                        "header " + header.getKey());
            }
            this.headers.put(header.getKey(), header.getValue());
        }
        return this;
    }

    public InboundAuthenticationRequestBuilder setCookies(Map<String, Cookie> cookies) {
        this.cookies = cookies;
        return this;
    }

    public InboundAuthenticationRequestBuilder addCookies(Map<String,Cookie> cookies) {
        for(Map.Entry<String,Cookie> cookie:cookies.entrySet()) {
            if(this.cookies.containsKey(cookie.getKey())) {
                throw AuthenticationFrameworkRuntimeException.error("Cookies map trying to override existing " +
                        "cookie " + cookie.getKey());
            }
            this.cookies.put(cookie.getKey(), cookie.getValue());
        }
        return this;
    }

    public InboundAuthenticationRequestBuilder setParameters(Map<String,String[]> parameters) {
        this.parameters = parameters;
        return this;
    }

    public InboundAuthenticationRequestBuilder addParameters(Map<String,String[]> parameters) {
        for(Map.Entry<String,String[]> parameter:parameters.entrySet()) {
            if(this.parameters.containsKey(parameter.getKey())) {
                throw AuthenticationFrameworkRuntimeException.error("Parameters map trying to override existing key " +
                        parameter.getKey());
            }
            this.parameters.put(parameter.getKey(), parameter.getValue());
        }
        return this;
    }

	public abstract String getName();

	public int getPriority() {
        return 0;
    }

	public abstract boolean canHandle(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationFrameworkRuntimeException;

	public InboundAuthenticationRequest build()
            throws AuthenticationFrameworkRuntimeException {

        return new InboundAuthenticationRequest(this);
    }

}
