@echo off 
schtasks /create /sc DAILY  /tn "UpgradeNnnmxAgent" /tr "C:\UpgradeAgent\upgradeagent.vbs" /rl highest /st 10:00 /ru Users
echo ===============================================================


