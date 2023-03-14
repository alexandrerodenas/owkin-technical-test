from docker.errors import APIError
from docker.models.containers import Container
from flask import Flask, request
import docker

from src.webapp.docker_container_service import DockerContainerService, VulnerableDockerImageException
from src.webapp.docker_image_scanner import DockerImageScanner

UPLOAD_FOLDER = 'dockerfiles'


class Api:
    def __init__(self, docker_container_service: DockerContainerService):
        self.docker_container_service = docker_container_service
        self.app = Flask(__name__)
        self.app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

        @self.app.route("/containers", methods=['POST'])
        def upload_dockerfile():
            if 'dockerfile' not in request.files:
                return "No dockerfile", 400

            dockerfile = request.files['dockerfile']
            if dockerfile.getbuffer().nbytes == 0:
                return "Empty dockerfile", 400

            dockerfile_path = '/tmp/Dockerfile'
            dockerfile.save(dockerfile_path)

            try:
                container = self.docker_container_service.create_and_run_container_from(dockerfile_path=dockerfile_path)
                return {'container_id': container.id}
            except VulnerableDockerImageException:
                return "Image having vulnerabilities", 400

        @self.app.route("/containers/<container_id>/status", methods=['GET'])
        def get_container_status(container_id):
            try:
                container: Container = self.docker_container_service.get_container(container_id=container_id)
                return {'job_status': container.status}
            except APIError as api_error:
                return api_error.explanation, api_error.status_code

        @self.app.route("/containers/<container_id>/performance", methods=['GET'])
        def get_container_performances(container_id):
            try:
                performance = self.docker_container_service.get_performance_of(container_id=container_id)
                return {'performance': performance}
            except APIError as api_error:
                return api_error.explanation, api_error.status_code

    def run(self):
        self.app.run()


if __name__ == '__main__':
    docker_client = docker.from_env()
    docker_image_scanner = DockerImageScanner(docker_client)
    docker_container_api = DockerContainerService(docker_image_scanner, docker_client)
    api = Api(
        docker_container_api
    )
    api.run()
