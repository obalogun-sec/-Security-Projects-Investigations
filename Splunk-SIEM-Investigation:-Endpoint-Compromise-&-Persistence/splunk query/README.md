1. index="lee-soc" host="FRONTDESK-PC1" sourcetype="*sysmon*" EventCode=1 | stats count by _time, Image, CommandLine





2. index="lee-soc" host="FRONTDESK-PC1" sourcetype="*sysmon*" EventCode=1 | sort _time | table _time, Image, ParentImage, CommandLine



3. index="lee-soc" host="FRONTDESK-PC1" sourcetype="*sysmon*" EventCode=3 Image="*python.exe"
