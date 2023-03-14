import json
import os
import unittest
from io import BytesIO

import docker

from src.webapp.api import Api
from src.webapp.docker_container_service import DockerContainerService
from src.webapp.docker_image_scanner import DockerImageScanner


class TestIntegration(unittest.TestCase):

    def setUp(self):
        docker_client = docker.from_env()
        docker_container_api = DockerContainerService(
            DockerImageScanner(
                docker_client
            ),
            docker_client
        )
        self.app = Api(
            docker_container_service=docker_container_api
        ).app.test_client()

    def test_can_create_and_get_performance_of_container(self):
        with open(os.path.dirname(__file__) + '/dockerfile', 'rb') as dockerfile:
            dockerfile_byte = BytesIO(dockerfile.read())

        response = self.app.post(
            '/containers', data={'dockerfile': (dockerfile_byte, 'dockerfile')}
        )
        container_id = response.json['container_id']

        current_status = None
        while not current_status == 'running':
            status_response = self.app.get('containers/'+container_id+'/status')
            current_status = status_response.json['job_status']
            if current_status == 'exited':
                raise Exception("Container exited")

        performance = self.app.get('containers/'+container_id+'/performance')

        assert performance.json['performance'] == 0.99

