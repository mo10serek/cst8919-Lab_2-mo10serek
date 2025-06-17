# Things learned in this lab

The Things I learned in this lab is that I can develop KQL queries in Azure to find different solutions from the table and able to access logs in the monitoring resource. Also, I can make different alert Rules in azure to notify me using email if there is a change in the resources used in azure. This is very useful to track and monitor the resources if something happened.

# Challenges 

The challenges faced during the lab is where I can find the sections in Log Analytics Workspace such as the Diagnostic settings and the alert rule in azure monitor. Also, when developing the application, not only I need to make a login endpoint for the application, but I need to connect it to Log Analytics workspace and send logs to it to see successful and failed login attempts. Another challenge is that I need to analyze the generated logs in the table to tell which logs failed or passed. I can tell this by code in the result description columns. If it 200 then it a pass but if it 401 then it is an error.

# KQL query

AppServiceConsoleLogs
| where ResultDescription contains "/login"
| where ResultDescription contains "401"
| project TimeGenerated, ResultDescription, _ResourceId
| sort by TimeGenerated desc

The first line is getting all the rows in the AppServiceConsoleLogs table.
The second line is getting all the rows that only have the "/login" endpoint.
The third line is getting all the rows what have the 401 code which means getting all the failed attempts
The fourth line is only displaying the Time Generated, Result Description, and the Resource Id columns.
The final line is sorted by time generated and description columns.

# Link for demo

[detecting failed login attempts](https://youtu.be/8ddCcPMUrzU).