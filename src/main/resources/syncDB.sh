#!/bin/sh

sourceDBUrl="<DB-conection_URL>" #The Connection URL of the APIM_2.1.0
sourceDBUser="<DB-Username>"
sourceDBPass="<Password>"
sourceDBDriver="com.mysql.jdbc.Driver"

destDBUrl="<DB-conection_URL>" #The Connection URL of the APIM_2.6.0
destDBUser="<DB-Username>"
destDBPass="<Password>"
destDBDriver="com.mysql.jdbc.Driver"

isEncryptionEnabled=false #Check whether the encryption is enabled in the source environment(APIM-2.1.0)

keystorePath="<APIM_2.6.0_HOME>/repository/resources/security/wso2carbon.jks" #The fully qualified path of the key-store
keystorePass="<password>"
keyAlias="<Alias>"
keyPass="<Key-password>"

java -jar org.wso2.carbon.migration.dbsync-1.0.0-jar-with-dependencies.jar \
$sourceDBUrl  $sourceDBUser  $sourceDBPass  $sourceDBDriver  $destDBUrl  $destDBUser  $destDBPass  $destDBDriver  \
$isEncryptionEnabled  $keystorePath  $keystorePass  $keyAlias  $keyPass