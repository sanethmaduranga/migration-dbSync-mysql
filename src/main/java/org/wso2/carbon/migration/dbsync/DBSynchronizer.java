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

package org.wso2.carbon.migration.dbsync;

import org.apache.log4j.PropertyConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.migration.dbsync.dto.AccessTokenDto;
import org.wso2.carbon.migration.dbsync.dto.AuthorizationCodeDto;
import org.wso2.carbon.migration.dbsync.dto.TokenScopeDto;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

public class DBSynchronizer {

    private static Logger logger = LoggerFactory.getLogger(DBSynchronizer.class);

    private static String sourceDBUrl;
    private static String sourceDBUser;
    private static String sourceDBPass;
    private static String sourceDBDriver;

    private static String destDBUrl;
    private static String destDBUser;
    private static String destDBPass;
    private static String destDBDriver;

    public static void main(String[] args) {

        PropertyConfigurator.configure("log4j.properties");
        logger.info("Starting database sync operation");

        sourceDBUrl = args[4];
        sourceDBUser = args[5];
        sourceDBPass = args[6];
        sourceDBDriver = args[7];

        destDBUrl = args[8];
        destDBUser = args[9];
        destDBPass = args[10];
        destDBDriver = args[11];

        try {

            DBSynchronizer dbSynchronizer = new DBSynchronizer();

            ArrayList<AccessTokenDto> accessTokenDtos = dbSynchronizer.readTokenInfo();
            logger.info("No of IDN_OAUTH2_ACCESS_TOKEN records to be merged: " + accessTokenDtos.size());
            dbSynchronizer.writeTokenInfo(accessTokenDtos);

            ArrayList<TokenScopeDto> tokenScopeDtos = dbSynchronizer.readTokenScope();
            logger.info("No of IDN_OAUTH2_ACCESS_TOKEN_SCOPE records to be merged: " + tokenScopeDtos.size());
            dbSynchronizer.writeTokenScope(tokenScopeDtos);

            ArrayList<AuthorizationCodeDto> authorizationCodeDtos = dbSynchronizer.readAuthCodes();
            logger.info("No of IDN_OAUTH2_AUTHORIZATION_CODE records to be merged: " + authorizationCodeDtos.size());
            dbSynchronizer.writeAuthCodes(authorizationCodeDtos);

        } catch (Exception e) {
            logger.error("Error occurred while running the db sync tool", e);
        }

    }

    private ArrayList<AccessTokenDto> readTokenInfo() {

        ArrayList<AccessTokenDto> accessTokenDtos = new ArrayList<AccessTokenDto>();
        Connection conn = null;
        ResultSet rs = null;
        PreparedStatement readStatement = null;
        try {
            Class.forName(sourceDBDriver);
            conn = DriverManager.getConnection(sourceDBUrl, sourceDBUser, sourceDBPass);
            String sql = "SELECT TOKEN_ID,ACCESS_TOKEN,REFRESH_TOKEN, CONSUMER_KEY_ID,AUTHZ_USER,TENANT_ID," +
                    "USER_DOMAIN,USER_TYPE,GRANT_TYPE,TIME_CREATED,REFRESH_TOKEN_TIME_CREATED,VALIDITY_PERIOD," +
                    "REFRESH_TOKEN_VALIDITY_PERIOD,TOKEN_SCOPE_HASH,TOKEN_STATE,TOKEN_STATE_ID,SUBJECT_IDENTIFIER FROM " +
                    "IDN_OAUTH2_ACCESS_TOKEN_SYNC";
            readStatement = conn.prepareStatement(sql);
            rs = readStatement.executeQuery();
            while (rs.next()) {
                AccessTokenDto accessTokenDto = new AccessTokenDto();
                accessTokenDto.setTokenId(rs.getString("TOKEN_ID"));
                accessTokenDto.setAccessToken(rs.getString("ACCESS_TOKEN"));
                accessTokenDto.setRefreshToken(rs.getString("REFRESH_TOKEN"));
                accessTokenDto.setConsumerKeyId(rs.getInt("CONSUMER_KEY_ID"));
                accessTokenDto.setAuthzUser(rs.getString("AUTHZ_USER"));
                accessTokenDto.setTenantId(rs.getInt("TENANT_ID"));
                accessTokenDto.setUserDomain(rs.getString("USER_DOMAIN"));
                accessTokenDto.setUserType(rs.getString("USER_TYPE"));
                accessTokenDto.setGrantType(rs.getString("GRANT_TYPE"));
                accessTokenDto.setTimeCreated(rs.getTimestamp("TIME_CREATED"));
                accessTokenDto.setRefreshTokenTimeCreated(rs.getTimestamp("REFRESH_TOKEN_TIME_CREATED"));
                accessTokenDto.setValidityPeriod(rs.getLong("VALIDITY_PERIOD"));
                accessTokenDto.setRefreshTokenValidityPeriod(rs.getLong("REFRESH_TOKEN_VALIDITY_PERIOD"));
                accessTokenDto.setTokenScopeHash(rs.getString("TOKEN_SCOPE_HASH"));
                accessTokenDto.setTokenState(rs.getString("TOKEN_STATE"));
                accessTokenDto.setTokenStateId(rs.getString("TOKEN_STATE_ID"));
                accessTokenDto.setSubjectIdentifier(rs.getString("SUBJECT_IDENTIFIER"));
                accessTokenDtos.add(accessTokenDto);
            }
        } catch (SQLException e) {
            logger.error("SQL Exception occurred", e);
        } catch (ClassNotFoundException e) {
            logger.error("Database Driver not found", e);
        } finally {
            try {
                if (rs != null) {
                    rs.close();
                }
                if (readStatement != null)
                    readStatement.close();
            } catch (SQLException e) {
                logger.error("SQL Exception occurred when closing statement", e);
            }
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException e) {
                logger.error("Connection close error", e);
            }
        }
        return accessTokenDtos;
    }

    private void writeTokenInfo(ArrayList<AccessTokenDto> accessTokenDtos) throws SQLException {

        PreparedStatement insertStatement = null;
        String insertQuery = "INSERT INTO IDN_OAUTH2_ACCESS_TOKEN (TOKEN_ID,ACCESS_TOKEN,REFRESH_TOKEN," +
                "CONSUMER_KEY_ID,AUTHZ_USER,TENANT_ID,USER_DOMAIN,USER_TYPE,GRANT_TYPE,TIME_CREATED," +
                "    REFRESH_TOKEN_TIME_CREATED,VALIDITY_PERIOD,REFRESH_TOKEN_VALIDITY_PERIOD,TOKEN_SCOPE_HASH," +
                "TOKEN_STATE,TOKEN_STATE_ID,SUBJECT_IDENTIFIER) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)" +
                "    ON DUPLICATE KEY UPDATE ACCESS_TOKEN = ?,REFRESH_TOKEN = ?, CONSUMER_KEY_ID = ?, AUTHZ_USER = ?," +
                " TENANT_ID = ?, USER_DOMAIN = ?, USER_TYPE = ?,GRANT_TYPE = ?, TIME_CREATED = ?," +
                "     REFRESH_TOKEN_TIME_CREATED = ?, VALIDITY_PERIOD = ?, REFRESH_TOKEN_VALIDITY_PERIOD = ?, " +
                "TOKEN_SCOPE_HASH = ?, TOKEN_STATE = ?, TOKEN_STATE_ID = ?, SUBJECT_IDENTIFIER = ?;";
        Connection conn = null;
        try {
            Class.forName(destDBDriver);
            conn = DriverManager.getConnection(destDBUrl, destDBUser, destDBPass);
            conn.setAutoCommit(false);
            insertStatement = conn.prepareStatement(insertQuery);
            for (AccessTokenDto accessTokenDto : accessTokenDtos) {
                insertStatement.setString(1, accessTokenDto.getTokenId());
                insertStatement.setString(2, accessTokenDto.getAccessToken());
                insertStatement.setString(3, accessTokenDto.getRefreshToken());
                insertStatement.setInt(4, accessTokenDto.getConsumerKeyId());
                insertStatement.setString(5, accessTokenDto.getAuthzUser());
                insertStatement.setInt(6, accessTokenDto.getTenantId());
                insertStatement.setString(7, accessTokenDto.getUserDomain());
                insertStatement.setString(8, accessTokenDto.getUserType());
                insertStatement.setString(9, accessTokenDto.getGrantType());
                insertStatement.setTimestamp(10, accessTokenDto.getTimeCreated());
                insertStatement.setTimestamp(11, accessTokenDto.getRefreshTokenTimeCreated());
                insertStatement.setLong(12, accessTokenDto.getValidityPeriod());
                insertStatement.setLong(13, accessTokenDto.getRefreshTokenValidityPeriod());
                insertStatement.setString(14, accessTokenDto.getTokenScopeHash());
                insertStatement.setString(15, accessTokenDto.getTokenState());
                insertStatement.setString(16, accessTokenDto.getTokenStateId());
                insertStatement.setString(17, accessTokenDto.getSubjectIdentifier());

                insertStatement.setString(18, accessTokenDto.getAccessToken());
                insertStatement.setString(19, accessTokenDto.getRefreshToken());
                insertStatement.setInt(20, accessTokenDto.getConsumerKeyId());
                insertStatement.setString(21, accessTokenDto.getAuthzUser());
                insertStatement.setInt(22, accessTokenDto.getTenantId());
                insertStatement.setString(23, accessTokenDto.getUserDomain());
                insertStatement.setString(24, accessTokenDto.getUserType());
                insertStatement.setString(25, accessTokenDto.getGrantType());
                insertStatement.setTimestamp(26, accessTokenDto.getTimeCreated());
                insertStatement.setTimestamp(27, accessTokenDto.getRefreshTokenTimeCreated());
                insertStatement.setLong(28, accessTokenDto.getValidityPeriod());
                insertStatement.setLong(29, accessTokenDto.getRefreshTokenValidityPeriod());
                insertStatement.setString(30, accessTokenDto.getTokenScopeHash());
                insertStatement.setString(31, accessTokenDto.getTokenState());
                insertStatement.setString(32, accessTokenDto.getTokenStateId());
                insertStatement.setString(33, accessTokenDto.getSubjectIdentifier());

                if (logger.isDebugEnabled()) {
                    logger.debug("Adding record to IDN_OAUTH2_ACCESS_TOKEN for the TOKEN ID: " + accessTokenDto.getTokenId());
                }
                insertStatement.addBatch();
            }
            insertStatement.executeBatch();
            conn.commit();
        } catch (SQLException e) {
            logger.error("SQL Exception occurred", e);
            conn.rollback();
        } catch (ClassNotFoundException e) {
            logger.error("Database Driver not found", e);
            conn.rollback();
        } catch (Exception e) {
            logger.error("An error occurred", e);
            conn.rollback();
        } finally {
            try {
                if (insertStatement != null)
                    insertStatement.close();
            } catch (SQLException e) {
                logger.error("SQL Exception occurred when closing statement", e);
            }
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException e) {
                logger.error("Connection close error", e);
            }
        }
    }

    private ArrayList<TokenScopeDto> readTokenScope() {

        ArrayList<TokenScopeDto> tokenScopeDtos = new ArrayList<TokenScopeDto>();
        Connection conn = null;
        ResultSet rs = null;
        PreparedStatement readStatement = null;
        try {
            Class.forName(sourceDBDriver);
            conn = DriverManager.getConnection(sourceDBUrl, sourceDBUser, sourceDBPass);
            String sql;
            sql = "SELECT TOKEN_ID,TOKEN_SCOPE,TENANT_ID FROM IDN_OAUTH2_ACCESS_TOKEN_SCOPE_SYNC";
            readStatement = conn.prepareStatement(sql);
            rs = readStatement.executeQuery();

            while (rs.next()) {
                TokenScopeDto tokenScopeDto = new TokenScopeDto();
                tokenScopeDto.setTokenId(rs.getString("TOKEN_ID"));
                tokenScopeDto.setTokenScope(rs.getString("TOKEN_SCOPE"));
                tokenScopeDto.setTenantId(rs.getInt("TENANT_ID"));
                tokenScopeDtos.add(tokenScopeDto);
            }
        } catch (SQLException e) {
            logger.error("SQL Exception occurred", e);
        } catch (ClassNotFoundException e) {
            logger.error("Database Driver not found", e);
        } finally {
            try {
                if (rs != null) {
                    rs.close();
                }
                if (readStatement != null)
                    readStatement.close();
            } catch (SQLException e) {
                logger.error("SQL Exception occurred when closing statement", e);
            }
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException e) {
                logger.error("Connection close error", e);
            }
        }
        return tokenScopeDtos;
    }

    private void writeTokenScope(ArrayList<TokenScopeDto> tokenScopeDtos) throws SQLException {

        PreparedStatement insertStatement = null;
        String insertQuery = "insert into IDN_OAUTH2_ACCESS_TOKEN_SCOPE (TOKEN_ID,TOKEN_SCOPE,TENANT_ID) " +
                "values (?, ?, ?) ON DUPLICATE KEY UPDATE TENANT_ID=?";

        Connection conn = null;
        try {
            Class.forName(destDBDriver);
            conn = DriverManager.getConnection(destDBUrl, destDBUser, destDBPass);
            conn.setAutoCommit(false);
            insertStatement = conn.prepareStatement(insertQuery);
            for (TokenScopeDto tokenScopeDto : tokenScopeDtos) {
                insertStatement.setString(1, tokenScopeDto.getTokenId());
                insertStatement.setString(2, tokenScopeDto.getTokenScope());
                insertStatement.setInt(3, tokenScopeDto.getTenantId());
                insertStatement.setInt(4, tokenScopeDto.getTenantId());

                if (logger.isDebugEnabled()) {
                    logger.debug("Adding record to IDN_OAUTH2_ACCESS_TOKEN_SCOPE for the TOKEN ID: " + tokenScopeDto.getTokenId());
                }
                insertStatement.addBatch();
            }
            insertStatement.executeBatch();
            conn.commit();
        } catch (SQLException e) {
            logger.error("SQL Exception occurred", e);
            conn.rollback();
        } catch (ClassNotFoundException e) {
            logger.error("Database Driver not found", e);
            conn.rollback();
        } finally {
            try {
                if (insertStatement != null) {
                    insertStatement.close();
                }
            } catch (SQLException e) {
                logger.error("SQL Exception occurred when closing statement", e);
            }
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException e) {
                logger.error("Connection close error", e);
            }
        }
    }

    private ArrayList<AuthorizationCodeDto> readAuthCodes() {

        ArrayList<AuthorizationCodeDto> authorizationCodeDtos = new ArrayList<AuthorizationCodeDto>();
        Connection conn = null;
        ResultSet rs = null;
        PreparedStatement readStatement = null;
        try {
            Class.forName(sourceDBDriver);
            conn = DriverManager.getConnection(sourceDBUrl, sourceDBUser, sourceDBPass);
            String sql;
            sql = "SELECT CODE_ID,AUTHORIZATION_CODE,CONSUMER_KEY_ID,CALLBACK_URL,SCOPE,AUTHZ_USER,TENANT_ID,USER_DOMAIN," +
                    "TIME_CREATED,VALIDITY_PERIOD,STATE,TOKEN_ID,SUBJECT_IDENTIFIER,PKCE_CODE_CHALLENGE,PKCE_CODE_CHALLENGE_METHOD" +
                    " FROM IDN_OAUTH2_AUTHORIZATION_CODE_SYNC";
            readStatement = conn.prepareStatement(sql);
            rs = readStatement.executeQuery();

            while (rs.next()) {
                AuthorizationCodeDto authzCodeDto = new AuthorizationCodeDto();
                authzCodeDto.setCodeId(rs.getString("CODE_ID"));
                authzCodeDto.setAuthorizationCode(rs.getString("AUTHORIZATION_CODE"));
                authzCodeDto.setConsumerKeyId(rs.getInt("CONSUMER_KEY_ID"));
                authzCodeDto.setCallbackUrl(rs.getString("CALLBACK_URL"));
                authzCodeDto.setScope(rs.getString("SCOPE"));
                authzCodeDto.setAuthzUser(rs.getString("AUTHZ_USER"));
                authzCodeDto.setTenantId(rs.getInt("TENANT_ID"));
                authzCodeDto.setUserDomain(rs.getString("USER_DOMAIN"));
                authzCodeDto.setTimeCreated(rs.getTimestamp("TIME_CREATED"));
                authzCodeDto.setValidityPeriod(rs.getLong("VALIDITY_PERIOD"));
                authzCodeDto.setState(rs.getString("STATE"));
                authzCodeDto.setTokenId(rs.getString("TOKEN_ID"));
                authzCodeDto.setSubjectIdentifier(rs.getString("SUBJECT_IDENTIFIER"));
                authzCodeDto.setPkceCodeChallenge(rs.getString("PKCE_CODE_CHALLENGE"));
                authzCodeDto.setPkceCodeChallengeMethod(rs.getString("PKCE_CODE_CHALLENGE_METHOD"));
                authorizationCodeDtos.add(authzCodeDto);
            }
            readStatement.close();
            conn.close();
        } catch (SQLException e) {
            logger.error("SQL Exception occurred", e);
        } catch (ClassNotFoundException e) {
            logger.error("Database Driver not found", e);
        } finally {
            try {
                if (rs != null) {
                    rs.close();
                }
                if (readStatement != null)
                    readStatement.close();
            } catch (SQLException e) {
                logger.error("SQL Exception occurred when closing statement", e);
            }
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException e) {
                logger.error("Connection close error", e);
            }
        }
        return authorizationCodeDtos;
    }

    private void writeAuthCodes(ArrayList<AuthorizationCodeDto> authorizationCodeDtos) throws SQLException {

        PreparedStatement insertStatement = null;
        String insertQuery = "insert into IDN_OAUTH2_AUTHORIZATION_CODE (CODE_ID,AUTHORIZATION_CODE," +
                "CONSUMER_KEY_ID,CALLBACK_URL,SCOPE,AUTHZ_USER,TENANT_ID,USER_DOMAIN,TIME_CREATED,VALIDITY_PERIOD,STATE," +
                "    TOKEN_ID,SUBJECT_IDENTIFIER,PKCE_CODE_CHALLENGE,PKCE_CODE_CHALLENGE_METHOD) values" +
                "    (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE AUTHORIZATION_CODE = ?, " +
                "CONSUMER_KEY_ID = ?,CALLBACK_URL =?, SCOPE = ?," +
                "AUTHZ_USER = ?,TENANT_ID = ?,USER_DOMAIN = ?," +
                "TIME_CREATED =?,VALIDITY_PERIOD = ?, STATE = ?," +
                "    TOKEN_ID = ?,SUBJECT_IDENTIFIER = ? ," +
                "PKCE_CODE_CHALLENGE = ?, PKCE_CODE_CHALLENGE_METHOD = ?;";

        Connection conn = null;
        try {
            Class.forName(destDBDriver);
            conn = DriverManager.getConnection(destDBUrl, destDBUser, destDBPass);
            conn.setAutoCommit(false);
            insertStatement = conn.prepareStatement(insertQuery);
            for (AuthorizationCodeDto authzCodeDto : authorizationCodeDtos) {
                insertStatement.setString(1, authzCodeDto.getCodeId());
                insertStatement.setString(2, authzCodeDto.getAuthorizationCode());
                insertStatement.setInt(3, authzCodeDto.getConsumerKeyId());
                insertStatement.setString(4, authzCodeDto.getCallbackUrl());
                insertStatement.setString(5, authzCodeDto.getScope());
                insertStatement.setString(6, authzCodeDto.getAuthzUser());
                insertStatement.setInt(7, authzCodeDto.getTenantId());
                insertStatement.setString(8, authzCodeDto.getUserDomain());
                insertStatement.setTimestamp(9, authzCodeDto.getTimeCreated());
                insertStatement.setLong(10, authzCodeDto.getValidityPeriod());
                insertStatement.setString(11, authzCodeDto.getState());
                insertStatement.setString(12, authzCodeDto.getTokenId());
                insertStatement.setString(13, authzCodeDto.getSubjectIdentifier());
                insertStatement.setString(14, authzCodeDto.getPkceCodeChallenge());
                insertStatement.setString(15, authzCodeDto.getPkceCodeChallengeMethod());

                insertStatement.setString(16, authzCodeDto.getAuthorizationCode());
                insertStatement.setInt(17, authzCodeDto.getConsumerKeyId());
                insertStatement.setString(18, authzCodeDto.getCallbackUrl());
                insertStatement.setString(19, authzCodeDto.getScope());
                insertStatement.setString(20, authzCodeDto.getAuthzUser());
                insertStatement.setInt(21, authzCodeDto.getTenantId());
                insertStatement.setString(22, authzCodeDto.getUserDomain());
                insertStatement.setTimestamp(23, authzCodeDto.getTimeCreated());
                insertStatement.setLong(24, authzCodeDto.getValidityPeriod());
                insertStatement.setString(25, authzCodeDto.getState());
                insertStatement.setString(26, authzCodeDto.getTokenId());
                insertStatement.setString(27, authzCodeDto.getSubjectIdentifier());
                insertStatement.setString(28, authzCodeDto.getPkceCodeChallenge());
                insertStatement.setString(29, authzCodeDto.getPkceCodeChallengeMethod());

                logger.debug("Adding record to IDN_OAUTH2_AUTHORIZATION_CODE with CODE ID: " + authzCodeDto.getCodeId());
                insertStatement.addBatch();
            }
            insertStatement.executeBatch();
            conn.commit();
        } catch (SQLException e) {
            logger.error("SQL Exception occurred", e);
            conn.rollback();
        } catch (ClassNotFoundException e) {
            logger.error("Database Driver not found", e);
            conn.rollback();
        } catch (Exception e) {
            logger.error("An error occurred", e);
            conn.rollback();
        } finally {
            try {
                if (insertStatement != null) {
                    insertStatement.close();
                }
            } catch (SQLException e) {
                logger.error("SQL Exception occurred when closing statement", e);
            }
            try {
                if (conn != null)
                    conn.close();
            } catch (SQLException e) {
                logger.error("Connection close error", e);
            }
        }
    }
}
