Output images/dashboard.gif

Require twlogeye

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 800
Set Padding 20
Set WindowBar Colorful

Type "twlogeye dashboard  monitor syslog.count netflow.count trap.count"
Sleep 500ms
Enter
Sleep 5s
Type "q"

Type "twlogeye dashboard  syslog.pattern syslog.error"
Sleep 500ms
Enter
Sleep 5s
Type "q"
