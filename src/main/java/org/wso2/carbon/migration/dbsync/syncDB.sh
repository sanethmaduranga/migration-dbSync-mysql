#!/bin/sh

sourceDBUrl="jdbc:mysql://localhost:3306/QANTAS_AM_01?autoReconnect=true&amp;useSSL=false"
sourceDBUser="root"
sourceDBPass="wso2123"
sourceDBDriver="com.mysql.jdbc.Driver"

destDBUrl="jdbc:mysql://localhost:3306/QANTAS_AM?autoReconnect=true&amp;useSSL=false"
destDBUser="root"
destDBPass="wso2123"
destDBDriver="com.mysql.jdbc.Driver"

isEncryptionEnabled=true

keystorePath="/home/saneth/Documents/SUPPORT/APIM/QANTASSUB-86/green_pack/wso2am-2.6.0/repository/resources/security/wso2carbon.jks"
keystorePass="wso2carbon"
keyAlias="wso2carbon"
keyPass="wso2carbon"

java -jar org.wso2.carbon.migration.dbsync-1.0.0-jar-with-dependencies.jar \
$sourceDBUrl  $sourceDBUser  $sourceDBPass  $sourceDBDriver  $destDBUrl  $destDBUser  $destDBPass  $destDBDriver  \
$isEncryptionEnabled  $keystorePath  $keystorePass  $keyAlias  $keyPass