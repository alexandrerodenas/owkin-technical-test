import unittest
from io import BytesIO
from unittest.mock import Mock, MagicMock

from docker.errors import APIError

from src.webapp.api import Api
from src.webapp.docker_container_service import VulnerableDockerImageException


def create_dockerfile_stream_from(dockerfile_content: bytes):
    dockerfile_stream = BytesIO(dockerfile_content)
    dockerfile_stream.name = 'Dockerfile'
    return dockerfile_stream


class TestCreateContainerFromDockerfile(unittest.TestCase):
    def setUp(self):
        self.mocked_docker_container_service = MagicMock()
        self.app = Api(
            docker_container_service=self.mocked_docker_container_service
        ).app.test_client()

    def test_can_create_container_from_dockerfile(self):
        dockerfile_stream = create_dockerfile_stream_from(b'FROM hello-world\n')
        mocked_container = Mock(id='mock_container_id')
        self.mocked_docker_container_service.create_and_run_container_from.return_value = mocked_container

        response = self.app.post(
            '/containers', data={'dockerfile': dockerfile_stream}
        )

        self.mocked_docker_container_service.create_and_run_container_from.assert_called_once_with(
            dockerfile_path='/tmp/Dockerfile'
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['container_id'], 'mock_container_id')

    def test_cannot_create_container_from_image_having_vulnerabilities(self):
        dockerfile_stream = create_dockerfile_stream_from(b'FROM hello-world\n')
        self.mocked_docker_container_service.create_and_run_container_from.side_effect = VulnerableDockerImageException()

        response = self.app.post(
            '/containers', data={'dockerfile': dockerfile_stream}
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data.decode('UTF-8'), "Image having vulnerabilities")

    def test_cannot_upload_no_dockerfile(self):
        data_with_no_dockerfile = {}

        response = self.app.post(
            '/containers', data={'dockerfile': data_with_no_dockerfile})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data.decode('UTF-8'), "No dockerfile")

    def test_cannot_upload_empty_dockerfile(self):
        dockerfile_stream = create_dockerfile_stream_from(b'')
        response = self.app.post(
            '/containers', data={'dockerfile': dockerfile_stream})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data.decode('UTF-8'), "Empty dockerfile")


class TestGetJobStatus(unittest.TestCase):
    def setUp(self):
        self.mocked_docker_container_service = MagicMock()
        self.app = Api(
            docker_container_service=self.mocked_docker_container_service
        ).app.test_client()

    def test_get_container_status(self):
        container_id = '1'
        mocked_container = Mock(id='1', status='running')
        self.mocked_docker_container_service.get_container.return_value = mocked_container

        response = self.app.get(f'/containers/{container_id}/status')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['job_status'], 'running')
        self.mocked_docker_container_service.get_container.assert_called_once_with(
            container_id=container_id
        )

    def test_exception_thrown_when_getting_not_existing_container(self):
        a_not_existing_container_id = '-1'
        self.mocked_docker_container_service.get_container.side_effect = APIError(
            explanation=f"No such container: {a_not_existing_container_id}",
            response=Mock(status_code=404),
            message=Mock()
        )

        response = self.app.get(f'/containers/{a_not_existing_container_id}/status')

        assert response.status_code == 404
        assert response.text == "No such container: -1"


class TestGetPerformance(unittest.TestCase):
    def setUp(self):
        self.mocked_docker_container_service = Mock()
        self.app = Api(
            docker_container_service=self.mocked_docker_container_service
        ).app.test_client()

    def test_can_get_performance_of_running_container(self):
        running_container_id = '1'
        running_container_performance = 95
        self.mocked_docker_container_service.get_performance_of.return_value = running_container_performance

        response = self.app.get(f'/containers/{running_container_id}/performance')

        assert response.status_code == 200
        assert response.json['performance'] == running_container_performance
        self.mocked_docker_container_service.get_performance_of.assert_called_once_with(
            container_id=running_container_id
        )


if __name__ == '__main__':
    unittest.main()
