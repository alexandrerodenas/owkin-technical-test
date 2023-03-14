# Instruction
Build a Restful API that let customer :

submit Dockerfile and get a job id
get status and performance if exists
Performance must be expressed as floating.

Once Dockerfile successfully uploaded :

* build the container
* scan for vulns

Depending on result :
* tag status as failed if vulns
* tag status as success if container was successfully build & run in isolated env

We would like container to write out his performance in `data/perf.json` which would be a volume mount point in `/data`.

# Run
Run tests to check available features  
Be sure to have docker installed and running before running integration test or application  
Run application from api.py

# Implementation choices
Api has been designed using framework Flask because it allows to design straight forward api without useless complexity.
For convenience reason, we chose to keep dockerfile in file running for five minutes.  
We chose _trivy_ as tool to detect vulnerabilities in docker image because it is open source and easy to use through docker sdk api.

# Improvements

## Code quality
* Some tests have implementation details knowledge such as 'data' directory in get_performance_of method
* Create abstraction ContainerService
* Create abstraction ImageScanner

## Code efficiency
* Find a way to make downloading of ghcr.io/aquasecurity/trivy-db faster
* Add consistency check on dockerfile in order to avoid useless image build
