# SPL Detection Queries

These are the main Splunk searches I used in this project with Sysmon Event ID 1 process creation data.

## Suspicious PowerShell Command-Line Activity

This search looks for PowerShell processes that use command-line arguments I wanted to monitor more closely.

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
"<EventID>1</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| where match(Image,"(?i)powershell\.exe$")
| where match(CommandLine,"(?i)(ExecutionPolicy\s+Bypass|EncodedCommand|-enc\b|-nop\b|NoProfile)")
| table _time User Image CommandLine ParentImage
| sort - _time
```

For testing, I ran:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SOC-LAB-DETECTION-1'"
```

This allowed me to confirm that the search detected the `NoProfile` and `ExecutionPolicy Bypass` arguments.

The search also includes patterns such as `EncodedCommand`, `-enc`, and `-nop`, but I did not generate those arguments during my testing.

These arguments are not automatically malicious, so the results are meant to be reviewed in context.

## Windows Reconnaissance Command Activity

This search looks for several common Windows commands that can be used to gather information about a system or user.

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
"<EventID>1</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| where match(Image,"(?i)(whoami|ipconfig|systeminfo|net)\.exe$")
| table _time User Image CommandLine ParentImage
| sort - _time
```

For testing, I ran:

```text
whoami
ipconfig
systeminfo
net user
```

I then confirmed that the related process creation events appeared in Splunk.

The search checks for `net.exe` because commands such as `net user` are executed through that Windows executable.

These are normal Windows utilities, but running several discovery commands close together can be useful context during an investigation.

## CMD Spawning PowerShell

This search looks for PowerShell being launched from Command Prompt.

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
"<EventID>1</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| where match(Image,"(?i)powershell\.exe$")
| where match(ParentImage,"(?i)cmd\.exe$")
| table _time User ParentImage Image CommandLine
| sort - _time
```

I tested this by launching PowerShell from Command Prompt with:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SOC-LAB-DETECTION-1'"
```

In Splunk, I was able to confirm that `cmd.exe` was recorded as the parent process and `powershell.exe` as the child process.

This parent-child relationship can be completely legitimate, but it provides useful context when reviewing PowerShell activity.
