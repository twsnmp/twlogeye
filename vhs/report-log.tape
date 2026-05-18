Output images/report-log.gif

Require twlogeye

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 800
Set Padding 20
Set WindowBar Colorful

Type "twlogeye log --logtype syslog"
Sleep 500ms
Enter
Sleep 3s

Type "twlogeye report syslog"
Sleep 500ms
Enter
Sleep 3s

Type "twlogeye report monitor"
Sleep 500ms
Enter
Sleep 3s
