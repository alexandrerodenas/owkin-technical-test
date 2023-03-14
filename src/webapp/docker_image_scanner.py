import json

from docker.errors import ContainerError


class ScanError(Exception):
    def __init__(self, message):
        self.message = message


class DockerImageScanner:
    def __init__(self, docker_client):
        self.docker_client = docker_client

    def scan_image_for_vulnerabilities(self, image_id: str):
        trivy_cmd = f'-q --format json image {image_id}'
        try:
            volume_name = '/var/run/docker.sock'
            mount_path = '/var/run/docker.sock'
            volumes = {volume_name: {'bind': mount_path, 'mode': 'rw'}}
            scan_results = self.docker_client.containers.run(
                'aquasec/trivy',
                trivy_cmd,
                remove=True,
                volumes=volumes
            )
            vulnerabilities = json.loads(scan_results)['Results'][0]['Vulnerabilities']

            return vulnerabilities
        except ContainerError as e:
            raise ScanError(e.stderr)

