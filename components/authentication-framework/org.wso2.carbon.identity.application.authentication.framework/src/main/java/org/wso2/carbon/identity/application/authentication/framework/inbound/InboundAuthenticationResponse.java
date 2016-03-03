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
 *
 */

package org.wso2.carbon.identity.application.authentication.framework.inbound;

import org.wso2.carbon.identity.base.IdentityRuntimeException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class InboundAuthenticationResponse implements Serializable {

    private static final long serialVersionUID = 4371843418083025682L;

    private Map<String, String> responseHeaders = new HashMap<String, String>();
    private Map<String, Cookie> cookies = new HashMap<String, Cookie>();
    private Map<String, String> parameters = new HashMap<String, String>();
    private int statusCode;
    private String redirectURL;

    public Map<String, String> getResponseHeaders() {
        return Collections.unmodifiableMap(responseHeaders);
    }

    public Map<String, Cookie> getCookies() {
        return Collections.unmodifiableMap(cookies);
    }

    public String getParameter(String key) {
        return getParameters().get(key);
    }

    public Map<String, String> getParameters() {
        return Collections.unmodifiableMap(parameters);
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getRedirectURL() {
        return redirectURL;
    }

    protected InboundAuthenticationResponse(InboundAuthenticationResponseBuilder builder) {
        this.responseHeaders = builder.responseHeaders;
        this.cookies = builder.cookies;
        this.parameters = builder.parameters;
        this.statusCode = builder.statusCode;
        this.redirectURL = builder.redirectURL;

    }

    public static class InboundAuthenticationResponseBuilder {

        private Map<String, String> responseHeaders = new HashMap<String, String>();
        private Map<String, Cookie> cookies = new HashMap<String, Cookie>();
        private Map<String, String> parameters = new HashMap<String, String>();
        private int statusCode;
        private String redirectURL;

        public String getName(){
            return "InboundAuthenticationResponseBuilder";
        }

        public int getPriority() {
            return 0;
        }

        protected InboundAuthenticationResponseBuilder() {

        }

        public InboundAuthenticationResponseBuilder setResponseHeaders(Map<String, String> responseHeaders) {
            this.responseHeaders = responseHeaders;
            return this;
        }

        public InboundAuthenticationResponseBuilder addResponseHeader(String key, String values) {
            responseHeaders.put(key, values);
            return this;
        }

        public InboundAuthenticationResponseBuilder setCookies(Map<String, Cookie> cookies) {
            this.cookies = cookies;
            return this;
        }

        public InboundAuthenticationResponseBuilder addCookie(String key, Cookie values) {
            cookies.put(key, values);
            return this;
        }

        public InboundAuthenticationResponseBuilder addParameter(String key, String value) {
            parameters.put(key, value);
            return this;
        }

        public InboundAuthenticationResponseBuilder addParameters(Map<String,String> parameters) {
            for(Map.Entry<String,String> parameter:parameters.entrySet()) {
                if(this.parameters.containsKey(parameter.getKey())) {
                    throw AuthenticationFrameworkRuntimeException.error("Parameters map trying to override existing key " + parameter
                            .getKey());
                }
                parameters.put(parameter.getKey(), parameter.getValue());
            }
            return this;
        }

        public InboundAuthenticationResponseBuilder setStatusCode(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        public InboundAuthenticationResponseBuilder setRedirectURL(String redirectURL) {
            this.redirectURL = redirectURL;
            return this;
        }

        public InboundAuthenticationResponse build() {
            return new InboundAuthenticationResponse(this);
        }

    }
}
