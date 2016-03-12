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

package org.wso2.carbon.identity.oauth2new;

import org.apache.commons.lang3.StringUtils;

public class OAuth2 {

    public static final long UNASSIGNED_VALIDITY_PERIOD = -1l;

    public static class TokenState {
        public static final String ACTIVE = "ACTIVE";
        public static final String INACTIVE = "INACTIVE";
        public static final String EXPIRED = "EXPIRED";
        public static final String REVOKED = "REVOKED";

        public static void validate(String tokenState) {
            if(StringUtils.isBlank(tokenState) || !StringUtils.equals(ACTIVE, tokenState) ||
                    !StringUtils.equals(INACTIVE, tokenState) || !StringUtils.equals(EXPIRED, tokenState) ||
                    !StringUtils.equals(REVOKED, tokenState)){
                throw new IllegalArgumentException("Invalid Token State " + tokenState);
            }
        }
    }

    public static final String AUTHZ_CODE = "AUTHZ_CODE";

    public class Header {
        public static final String CACHE_CONTROL = "Cache-Control";
        public static final String PRAGMA = "Pragma";
    }

    public class HeaderValue {
        public static final String CACHE_CONTROL_NO_STORE = "no-store";
        public static final String PRAGMA_NO_CACHE = "no-cache";
    }
}
