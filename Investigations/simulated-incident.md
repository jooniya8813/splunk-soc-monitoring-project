# Simulated Incident Investigation

For this project, I generated a small amount of test activity so I could practice finding and reviewing it in Splunk.

## Test Activity

I ran:

```text
whoami
systeminfo
ipconfig
net user
```

I also launched PowerShell with:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SOC-LAB-DETECTION-1'"
```

## What I Found

Using Sysmon Event ID 1 in Splunk, I was able to see the user, process, command line, and parent process for the activity.

I also confirmed that `cmd.exe` launched `powershell.exe`.

## Detection Tuning

My first reconnaissance search also matched `Battle.net.exe` because it ended in `net.exe`.

I changed the search to use exact process names, which removed the false positive.

## Takeaway

This helped me get more comfortable reviewing process activity in Splunk and adjusting a detection when the results were too broad.
