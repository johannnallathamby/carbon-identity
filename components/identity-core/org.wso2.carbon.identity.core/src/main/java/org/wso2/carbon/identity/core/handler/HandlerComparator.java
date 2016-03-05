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

import org.wso2.carbon.identity.core.bean.context.MessageContext;

import java.util.Comparator;

/*
 * Comparator for sorting handler collection
 */
public class HandlerComparator implements Comparator<HandlerComparable>  {

    private MessageContext messageContext = null;

    public HandlerComparator(MessageContext messageContext){
        this.messageContext = messageContext;
    }

    @Override
    public int compare(HandlerComparable o1, HandlerComparable o2) {

        if (o1.getPriority(messageContext) > o2.getPriority(messageContext)) {
            return 1;
        } else if (o1.getPriority(messageContext) == o2.getPriority(messageContext)) {
            return 0;
        } else {
            return -1;
        }
    }
}
