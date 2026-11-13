import csv
import configparser
import requests
import time
import json

#read api key
config =configparser.ConfigParser()
config.read("config.ini")

api_key =config["AbuseIPDB"]["api_key"]


def check_ip(ip):
    url ="https://api.abuseipdb.com/api/v2/check"

    headers ={
        "Key": api_key,
        "Accept": "application/json"
    }

    params ={
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response =requests.get(
            url,
            headers=headers,
            params=params,
            timeout=10
        )

        if response.status_code == 200:
            data =response.json()
            return data["data"]
        else:
            print("API Error:", response.status_code)
            return None

    except Exception as e:
        print("Connection failed:", e)
        return None


#Store final result
results = []

#to avoid checking the same ip twice
checked_ips = {}

with open("connections.csv", "r") as file:
    reader =csv.DictReader(file)

    for row in reader:

        ip =row["RemoteAddress"]
        process =row["ProcessName"]

        print("Checking:", ip, "-",process)

        #check if we already looked up this ip
        if ip in checked_ips:
            api_result =checked_ips[ip]

        else:
            api_result =check_ip(ip)
            checked_ips[ip] =api_result
            time.sleep(0.3)

        if api_result:

            score =api_result["abuseConfidenceScore"]

            if score >= 80:
                threat_level = "HIGH"

            elif score >= 30:
                threat_level = "MEDIUM"

            else:
                threat_level = "LOW"

            result = {
                "IP": ip,
                "Process":process,
                "Port":row["RemotePort"],
                "PID":row["PID"],
                "ThreatScore":score,
                "ThreatLevel":threat_level,
                "Country":api_result.get("countryCode", "Unknown"),
                "ISP":api_result.get("isp", "Unknown")
            }

            results.append(result)


print("")
print("Threat Analysis Results")
print("-----------------------")

for result in results:
    print(
        result["IP"],
        "-",
        result["Process"],
        "- Score:",
        result["ThreatScore"],
        "-",
        result["ThreatLevel"]
    )



#Saveresults to CSV
with open("threat_report.csv", "w", newline="") as file:
    fieldnames = [
        "IP",
        "Process",
        "Port",
        "PID",
        "ThreatScore",
        "ThreatLevel",
        "Country",
        "ISP"
    ]

    writer = csv.DictWriter(file, fieldnames=fieldnames)

    writer.writeheader()
    writer.writerows(results)

print("Results saved to threat_report.csv")



#Saving result to jSON
with open("threat_report.json", "w") as file:
    json.dump(results, file, indent=4)

print("Results saved to threat_report.json")


high =0
medium =0
low =0

for result in results:
    if result["ThreatLevel"] == "HIGH":
        high += 1
    elif result["ThreatLevel"] == "MEDIUM":
        medium += 1
    else:
        low += 1

print("")
print("Summary")
print("-------")
print("Total results:", len(results))
print("High:", high)
print("Medium:", medium)
print("Low:", low)
