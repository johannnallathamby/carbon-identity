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

package org.wso2.carbon.identity.oauth2new.dao;

import org.wso2.carbon.identity.oauth2new.dao.jdbc.JDBCOAuth2DAO;

public class CacheBackedOAuth2DAO implements OAuth2DAO {

    private static volatile OAuth2DAO instance = null;
    private OAuth2DAO wrappedDAO;

    private CacheBackedOAuth2DAO(OAuth2DAO dao) {
        this.wrappedDAO = dao;
    }

    public static OAuth2DAO getInstance() {
        if(instance == null) {
            synchronized (CacheBackedOAuth2DAO.class) {
                if(instance == null) {
                    instance = new CacheBackedOAuth2DAO(JDBCOAuth2DAO.getInstance());
                }
            }
        }
        return instance;
    }
}
