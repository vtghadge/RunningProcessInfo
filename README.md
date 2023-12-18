ReadMe.txt
==========

- **Utility:** Gathering Running Process Data Through Process Hollowing
- **Author:** Vishal Ghadge
- **Email:** vtghadge@gmail.com

Problem Statement:
==================

1. Part1
	- Create a C++ Windows 11 executable that launches another application, such as a
svchost.exe or another long-running non-UI application
	- Modify the newly launched process so that it's only job is to periodically (say once every
minute) obtain a list of running processes and send it to a specific URL.
2. Part2:
	- Implement a URL listener that receives data from the app above.
	
Solution:
=========
I chose process hollowing for its ability to inject code into a separate process,
enabling stealthy execution and evading detection.
Alternatives such as DLL injection and API hooking exist, but process hollowing often provides better obfuscation and can be more difficult to detect.

Build Environment:
==================

1. Visual Studio 2019 (v142)

Building RunningProcessInfo solution:
==============================

1. Unpack the entire archive into an empty directory.
2. Open the workspace `RunningProcessInfo.sln`.
3. Select `Build -> Batch build`.
4. Currently only supported for the x64 platform.
5. Click on `Rebuild`.

Modules:
========

1. **AppLauncher Module:**
    - A Windows console application that engages in process hollowing by launching svchost in suspended mode..
    - It unmaps the legitimate image of svchost and substitutes it with the RunningProcessList image for concealment..

2. **RunningProcessList Module:**
    - A Windows window application that operates continuously in the background..
    - Upon initialization, it queries server URL information to determine where data needs to be sent.
    - It persists in running continuously, gathering running process information every minute and transforming it into JSON format.
    - The collected JSON process data is then transmitted to the server.
    - This process continues to run until the system undergoes shutdown and can be manually terminated using the PID displayed on the console.

3. **UrlListener Module:**
    - A Windows console application designed for fetching running process information from the server..
    - During initialization, it queries server URL information to identify the location from which data needs to be fetched.
    - At one-minute intervals, it retrieves running process information from the server if a new request is present.
    - The process can be terminated using Ctrl+C.

Config.ini Format:
===================

**Config.ini:**
This config file must be present in the product directory. RunningProcessList and UrlListener modules use this file.

[Server]
ApiId=c2455784-3080-4ce9-a19b-16deb0051ea0
ServerUrl=https://webhook.site/c2455784-3080-4ce9-a19b-16deb0051ea0

[Client]
ApiId=c2455784-3080-4ce9-a19b-16deb0051ea0
TokenUrl=https://webhook.site/token/c2455784-3080-4ce9-a19b-16deb0051ea0
RequestUrl=https://webhook.site/token/c2455784-3080-4ce9-a19b-16deb0051ea0/request/

1. The RunningProcessList module reads the ServerUrl value and uses this URL to send data to the WebHook server.
Note: This URL is temporarily created; feel free to replace it with a new URL.
2. The UrlListener module uses values from the [Client] section:
	- "TokenUrl" is used to query the latest request ID from the server.
	- "RequestUrl" is used to construct the request URL using the latest request ID to fetch the most recent data from the server.

Usage:
=======
1. Launch AppLauncher.exe from one command prompt:
	-Initiates the sending of process info events to the server in the background.
	-Operates continuously until system shutdown.
	-Manually terminate using the process ID from the console.
	-Monitor the URL https://webhook.site/#!/c2455784-3080-4ce9-a19b-16deb0051ea0 to check for the latest events.
2. Launch UrlListener from another command prompt:
	-Fetches and prints process info from the server.
	-Terminate using Ctrl+C.
3. Ensure that the config.ini file is located in the binary folder, check BinarySet folder.	
	
Testcases:
==========
1. Monitor the URL https://webhook.site/#!/c2455784-3080-4ce9-a19b-16deb0051ea0 to check for the latest events.
2. Monitor UrlListener console to verify if it shows process info updates every minute.
3. If "Process hollowing failed" is displayed, the replacement of the RunningProcessList image with the svchost image failed.

Pending:
========
1. Pending tasks include sending data in protobuf format.
2. 32-bit platform support is still pending.
3. Testing the application with the Application Verifier.

Known Issues:
=============
1. 32-bit platform support is currently missing.
2. RunningProcessList remains in a running state, lacking proper termination handling.