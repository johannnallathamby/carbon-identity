/*
*Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*WSO2 Inc. licenses this file to you under the Apache License,
*Version 2.0 (the "License"); you may not use this file except
*in compliance with the License.
*You may obtain a copy of the License at
*
*http://www.apache.org/licenses/LICENSE-2.0
*
*Unless required by applicable law or agreed to in writing,
*software distributed under the License is distributed on an
*"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
*KIND, either express or implied.  See the License for the
*specific language governing permissions and limitations
*under the License.
*/

package org.wso2.carbon.identity.core.handler;

import org.apache.commons.collections.map.HashedMap;
import org.wso2.carbon.identity.base.IdentityRuntimeException;

import java.util.Collections;
import java.util.Map;

public class HandlerInfo<T1,T2,T3> {

    private T1 returnValue;
    private HandlerReturnStatus previousStatus;
    private Map<T2,T3> parameters = new HashedMap();

    public HandlerInfo(T1 returnValue, HandlerReturnStatus previousStatus, Map<T2, T3> parameters) {
        this.returnValue = returnValue;
        this.previousStatus = previousStatus;
        this.parameters = parameters;
    }

    public HandlerInfo(Map<T2, T3> parameters) {
        this.parameters = parameters;
    }

    public T1 getReturnValue() {
        return returnValue;
    }

    public HandlerReturnStatus getPreviousStatus() {
        return previousStatus;
    }

    public void addParameter(T2 key, T3 value) {
        if(this.parameters.containsKey(key)) {
            throw IdentityRuntimeException.error("Parameters map trying to override existing key " +
                    key);
        }
        parameters.put(key, value);
    }

    public void addParameters(Map<T2,T3> parameters) {
        for (Map.Entry<T2,T3> parameter : parameters.entrySet()) {
            if(this.parameters.containsKey(parameter.getKey())) {
                throw IdentityRuntimeException.error("Parameters map trying to override existing key " + parameter.getKey());
            }
            parameters.put(parameter.getKey(), parameter.getValue());
        }
    }

    public Map<T2,T3> getParameters(){
        return Collections.unmodifiableMap(parameters);
    }

    public T3 getParameter(T2 key){
        return parameters.get(key);
    }

}
