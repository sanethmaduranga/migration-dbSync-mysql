/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.migration.dbsync.dto;

import java.sql.Timestamp;

public class AccessTokenDto {

    private String tokenId;
    private String accessToken;
    private String refreshToken;
    private int consumerKeyId;
    private String authzUser;
    private int tenantId;
    private String userDomain;
    private String userType;
    private String grantType;
    private Timestamp timeCreated;
    private Timestamp refreshTokenTimeCreated;
    private long validityPeriod;
    private long refreshTokenValidityPeriod;
    private String tokenScopeHash;
    private String tokenState;
    private String tokenStateId;
    private String subjectIdentifier;

    public String getTokenId() {
        return tokenId;
    }

    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public int getConsumerKeyId() {
        return consumerKeyId;
    }

    public void setConsumerKeyId(int consumerKeyId) {
        this.consumerKeyId = consumerKeyId;
    }

    public String getAuthzUser() {
        return authzUser;
    }

    public void setAuthzUser(String authzUser) {
        this.authzUser = authzUser;
    }

    public int getTenantId() {
        return tenantId;
    }

    public void setTenantId(int tenantId) {
        this.tenantId = tenantId;
    }

    public String getUserDomain() {
        return userDomain;
    }

    public void setUserDomain(String userDomain) {
        this.userDomain = userDomain;
    }

    public String getUserType() {
        return userType;
    }

    public void setUserType(String userType) {
        this.userType = userType;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public Timestamp getTimeCreated() {
        return timeCreated;
    }

    public void setTimeCreated(Timestamp timeCreated) {
        this.timeCreated = timeCreated;
    }

    public Timestamp getRefreshTokenTimeCreated() {
        return refreshTokenTimeCreated;
    }

    public void setRefreshTokenTimeCreated(Timestamp refreshTokenTimeCreated) {
        this.refreshTokenTimeCreated = refreshTokenTimeCreated;
    }

    public long getValidityPeriod() {
        return validityPeriod;
    }

    public void setValidityPeriod(long validityPeriod) {
        this.validityPeriod = validityPeriod;
    }

    public long getRefreshTokenValidityPeriod() {
        return refreshTokenValidityPeriod;
    }

    public void setRefreshTokenValidityPeriod(long refreshTokenValidityPeriod) {
        this.refreshTokenValidityPeriod = refreshTokenValidityPeriod;
    }

    public String getTokenScopeHash() {
        return tokenScopeHash;
    }

    public void setTokenScopeHash(String tokenScopeHash) {
        this.tokenScopeHash = tokenScopeHash;
    }

    public String getTokenState() {
        return tokenState;
    }

    public void setTokenState(String tokenState) {
        this.tokenState = tokenState;
    }

    public String getTokenStateId() {
        return tokenStateId;
    }

    public void setTokenStateId(String tokenStateId) {
        this.tokenStateId = tokenStateId;
    }

    public String getSubjectIdentifier() {
        return subjectIdentifier;
    }

    public void setSubjectIdentifier(String subjectIdentifier) {
        this.subjectIdentifier = subjectIdentifier;
    }
}

