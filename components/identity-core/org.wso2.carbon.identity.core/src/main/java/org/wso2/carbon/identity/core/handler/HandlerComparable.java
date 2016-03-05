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

package org.wso2.carbon.identity.core.handler;

import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;

/**
 * This interface needs to be implemented by any identity/extension handler.
 * This is used to sort the handlers according to priority
 */
public interface HandlerComparable {

    /**
     * Used to sort the set of handlers
     *
     * @param messageContext The runtime message context
     * @return The priority value of the handler
     * @throws IdentityRuntimeException
     */
    public int getPriority(MessageContext messageContext) throws IdentityRuntimeException;

}
