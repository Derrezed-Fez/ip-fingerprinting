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