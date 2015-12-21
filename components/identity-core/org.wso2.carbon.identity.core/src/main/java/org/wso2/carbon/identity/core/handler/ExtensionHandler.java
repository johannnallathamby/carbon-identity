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

import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;

import java.util.Properties;

/**
 * This interface needs to be implemented by any extension handler.
 */
public abstract class ExtensionHandler implements HandlerComparable {

    protected Properties properties = new Properties();

    /**
     * Initialize the Extension Handler
     * @throws IdentityRuntimeException Error when initializing the authorization grant handler
     */
    public void init(Properties properties) throws IdentityRuntimeException {
        if(properties != null){
            this.properties = properties;
        }
    }

    public boolean isEnabled(MessageContext messageContext) throws IdentityException {
        return true;
    }

    public boolean isEnabled() throws IdentityException {
        return true;
    }

    /**
     * Tells if this request can be handled by this handler
     *
     * @param messageContext <code>MessageContext</code>
     * @return <code>ExtHandlerReturnStatus</code>
     * @throws IdentityRuntimeException
     */
    public abstract boolean canHandle(MessageContext messageContext) throws IdentityRuntimeException;

    /**
     * Tells if this request can be handled by this handler
     *
     * @return <code>ExtHandlerReturnStatus</code>
     * @throws IdentityRuntimeException
     */
    public abstract boolean canHandle() throws IdentityRuntimeException;


    /**
     * Handles the request
     *
     * @param messageContext <code>MessageContext</code>
     * @throws IdentityRuntimeException
     */
    public abstract HandlerReturnStatus handle(MessageContext messageContext) throws IdentityRuntimeException;

    /**
     * Handles the request
     *
     * @throws IdentityRuntimeException
     */
    public abstract HandlerReturnStatus handle() throws IdentityRuntimeException;

}
