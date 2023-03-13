## Data Sources
** TRANCO ** https://tranco-list.eu/list/3VJ5L/1000000
** ALEXA TOP 1 MIL ** http://s3.amazonaws.com/alexa-static/top-1m.csv.zip

## Running Sitespeedio
* Tool resources: https://www.sitespeed.io/documentation/browsertime/
* Pull and run the Docker image (Windows): docker run --rm -v <your-home-directory>:/browsertime sitespeedio/browsertime:17.1.0 https://www.sitespeed.io -b firefox
* Create a docker container with options:  docker create sitespeedio/browsertime https://www.sitespeed.io -b firefox
### If using NPM
* npm i -g sitespeed.io
* npm install browsertime -g
* cd <user>\AppData\Roaming\npm
* browsertime https://www.sitepeed.io -b firefox
* logs are located at <user>\AppData\Roaming\npm\browsertime-results

To run the tool in Windows:
1. Make sure the domains CSV file is accurate of what you want to crawl in data/input.
2. Run Powershell as administrator. Execute the command Set-ExecutionPolicy RemoteSigned and select Yes to All
3. Run python3 browsertime_crawler.py in a terminal (don't close the terminal!)
4. Monitor the output folder (<home-directory>:/AppData/Roaming/npm/browsertime-results)
5. Each domain directory should have 3 entries (one for each browser). The JSON file contained inside will be labeled by browser.
6. Run HAR parser (WIP) against each domain folder to extract the DNS requests and times to load. Need to parse each HAR file and transpose to create the same file structure as was in the original dataset.