import os

from docker.errors import BuildError, APIError
from docker.models.containers import Container
import json


class VulnerableDockerImageException(Exception):
    def __init__(self):
        self.message = "Vulnerabilities detected in image"


class ImageBuildException(Exception):
    def __init__(self, message):
        self.message = message


class DockerContainerService:

    def __init__(self, docker_image_scanner, docker_client):
        self.docker_client = docker_client
        self.docker_image_scanner = docker_image_scanner

    def create_and_run_container_from(self, dockerfile_path):
        try:
            image, logs = self.docker_client.images.build(
                path=os.path.dirname(dockerfile_path),
                dockerfile='Dockerfile',
                tag='test'
            )

            vulnerabilities = self.docker_image_scanner.scan_image_for_vulnerabilities(
                image.tags[0].split(':')[0]
            )

            high_vulnerabilities = list(filter(lambda v : v['Severity'] == 'HIGH', vulnerabilities))
            if len(high_vulnerabilities) > 0:
                raise VulnerableDockerImageException()
            return self.docker_client.containers.run(
                image,
                detach=True
            )
        except BuildError as error:
            raise ImageBuildException(error.msg)
        except APIError as error:
            raise ImageBuildException(error.explanation)

    def get_container(self, container_id) -> Container :
        return self.docker_client.containers.get(container_id=container_id)

    def get_performance_of(self, container_id):
        container = self.get_container(container_id)
        performance = container.exec_run('cat /data/perf.json').output
        performance_as_json = json.loads(performance.decode('UTF-8'))
        return float(performance_as_json['perf'])



