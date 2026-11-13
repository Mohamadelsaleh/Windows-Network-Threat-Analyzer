window network threat analyzer

the project uses PowerShell and Python to check active network connections on a Windows computer. powershell collects the remote IP address port PID and process name and saves the information to connections.csv

python reads the csv file and checks the remote IP addresses using the abuseipdb  apI.each iP is given a threat score and classified as low, medium or high. final results are saved in threat\_report.csv and threat\_report.json.

project requires Windows, powershell Python3,an internet connection an abuseipdb apI key and the python "requests" library.

install the required library using:

text

pip install requests

the API key is added to config.ini:

AbuseIPDB

api\_key =API\_KEY

run PowerShell first:

powershell

.\\network\_audit.ps1

Then run Python:

python "threat\_analyzer.py"

the tool helps a security analyst see which process is connected to a remote IP and whether that IP has a suspicious reputation.

