$filePath = "C:\nnmx_agent\nnmx_agent.exe"
# Add file exclusion to Windows Security
Add-MpPreference -ExclusionPath $filePath


$filePath2 = "C:\UpgradeAgent\upgrade_agent.exe"
Add-MpPreference -ExclusionPath $filePath2