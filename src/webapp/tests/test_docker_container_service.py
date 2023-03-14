import os
import unittest
from unittest.mock import MagicMock, Mock, patch

import pytest
from docker.errors import BuildError
from docker.models.containers import ExecResult

from src.webapp.docker_container_service import \
    DockerContainerService, VulnerableDockerImageException, ImageBuildException
from src.webapp.docker_image_scanner import DockerImageScanner


class TestDockerContainerApiCreation(unittest.TestCase):
    @patch("docker.from_env")
    def setUp(self, mocked_docker_client):
        self.mocked_docker_client = mocked_docker_client
        self.mocked_image_scanner = MagicMock(spec=DockerImageScanner)
        self.mocked_container = MagicMock(id='mock_container_id', attrs={})
        self.docker_container_service = DockerContainerService(
            self.mocked_image_scanner,
            self.mocked_docker_client
        )

    def test_image_with_no_high_vulnerabilities_is_run(self):
        self.mocked_docker_client.containers.run.return_value = self.mocked_container
        self.mocked_image_scanner.scan_image_for_vulnerabilities.return_value = [
            {'Severity': 'MEDIUM'},
            {'Severity': 'LOW'}
        ]
        mocked_image = Mock(id='mock_image_id', short_id="mock_short_id", tags=['test:latest'])
        mock_logs = 'mock_logs'
        self.mocked_docker_client.images.build.return_value = (mocked_image, mock_logs)

        container = self.docker_container_service.create_and_run_container_from('/tmp/Dockerfile')

        assert container == self.mocked_container
        self.mocked_docker_client.images.build.assert_called_once_with(
            path=os.path.dirname('/tmp/Dockerfile'),
            dockerfile='Dockerfile',
            tag='test'
        )
        self.mocked_docker_client.containers.run.assert_called_once_with(
            mocked_image,
            detach=True
        )
        self.mocked_image_scanner.scan_image_for_vulnerabilities.assert_called_once_with(
            'test'
        )

    def test_an_exception_is_thrown_when_image_cannot_be_built(self):
        with pytest.raises(ImageBuildException) as exception:
            self.mocked_docker_client.images.build.side_effect = BuildError("Error when building", "")
            self.docker_container_service.create_and_run_container_from('/tmp/Dockerfile')

        assert exception.value.message == 'Error when building'

    def test_an_exception_is_thrown_with_image_having_high_vulnerabilities(self):
        with pytest.raises(VulnerableDockerImageException) as exception:
            self.mocked_docker_client.containers.run.return_value = self.mocked_container
            mocked_image = Mock(id='mock_image_id', tags=['test:latest'])
            mock_logs = 'mock_logs'
            self.mocked_docker_client.images.build.return_value = (mocked_image, mock_logs)
            self.mocked_image_scanner.scan_image_for_vulnerabilities.return_value = [{'Severity': 'HIGH'}]

            self.docker_container_service.create_and_run_container_from('/tmp/Dockerfile')

        assert exception.value.message == 'Vulnerabilities detected in image'


class TestDockerContainerGetterApi(unittest.TestCase):

    @patch("docker.from_env")
    def test_can_get_container_from_id(self, mocked_docker_client):
        mocked_container = Mock(id='a_container_id')
        mocked_docker_client.containers.get.return_value = mocked_container

        container = DockerContainerService(
            Mock(),
            mocked_docker_client
        ).get_container('a_container_id')

        assert container.id == mocked_container.id
        mocked_docker_client.containers.get.assert_called_once_with(
            container_id='a_container_id'
        )


class TestDockerContainerPerformanceApi(unittest.TestCase):

    @patch("docker.from_env")
    def test_can_get_container_performance_from_id(self, mocked_docker_client):
        mocked_container = Mock(id='a_container_id')
        mocked_container.exec_run.return_value = ExecResult(0, b'{"perf":"0.99"}')
        mocked_docker_client.containers.get.return_value = mocked_container

        performance = DockerContainerService(
            Mock(),
            mocked_docker_client
        ).get_performance_of('a_container_id')

        assert performance == 0.99
        mocked_docker_client.containers.get.assert_called_once_with(
            container_id='a_container_id'
        )


if __name__ == '__main__':
    unittest.main()
