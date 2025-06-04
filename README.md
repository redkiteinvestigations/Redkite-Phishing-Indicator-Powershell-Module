==============================================
Welcome to RedKite Phishing Indicators Checker


RedKite is a PowerShell-based tool designed to assist security analysts and administrators in detecting suspicious mailbox configurations that might indicate email phishing attacks in Exchange Online environments. It checks for suspicious inbox rules, external redirects, and recent mailbox changes that could indicate a compromised account.

Features
🔍Suspicious Inbox Rules: Detects inbox rules that:

Delete or mark messages as read

Move messages to folders silently

Forward emails externally

External Forwards: Identifies rules that forward mail outside of accepted domains.

Recent Mailbox Changes: Highlights recent changes to mailbox configurations (optional step).

Logging: Saves logs in timestamped log files in the specified directory.

CSV Export: Allows easy export of results for reporting and analysis.

=========================

🔧 Prerequisites
PowerShell 5.1 or later

Admin privileges in Exchange Online and Microsoft Graph

Installed modules:

Microsoft.Graph

ExchangeOnlineManagement

===========================
🚀 Usage

Run in powershell:

Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser

Import the module
Make sure the .psm1 file is in your module path, or import it directly:

Import-Module .\Redkite.psm1

This will check for required modules
Microsoft.Graph and ExchangeOnlineManagement
Ensure these are installed and imported into the powershell session

Run the command 'Start-RedKite'

Follow prompts to:

Select users (all or specific) 
- You can enter a specific user, several users in succession, or select all users

Specify log folder
- Log file output path can be specified. This defaults to the documents folder and creates the output into a folder called 'RedkiteLogs' 

Choose lookback days
-This is used for recent mailbox changes and defaults to 90 days

Export results to CSV (optional)
- Export path can be specified. This creates a folder called 'RedkiteResults' in the documents folder by default and saves the output as a CSV file.

Disconnect from services (optional)
- This disconnects form Exchange online and Microsoft Graph 

=========================


⚠️ Notes
RedKite is designed to assist investigations, not replace them.

Always verify suspicious findings manually.

Requires appropriate administrative privileges in Exchange Online and Microsoft Graph.

=========================

🤝 Contributions
Contributions are welcome! Please fork the repository and submit a pull request or open an issue with your suggestions.

Project Uri
https://github.com/redkiteinvestigations/Redkite-Phishing-Indicator-Powershell-Module

==========================

📄 License
This module is provided as-is with no warranty. Use at your own risk.

License Uri
https://github.com/redkiteinvestigations/Redkite-Phishing-Indicator-Powershell-Module/blob/c5ec6598c15fa326f3528cd63ba3666b8414a5b9/License.txt

==========================

📄 Certificate
A self signed certificate has been supplied if required

Certificate Uri
https://github.com/redkiteinvestigations/Redkite-Phishing-Indicator-Powershell-Module/blob/c5ec6598c15fa326f3528cd63ba3666b8414a5b9/redkite2025.cer
