import json
import unittest
from unittest.mock import patch, Mock

import pytest
from docker.errors import ContainerError

from src.webapp.docker_image_scanner import DockerImageScanner, ScanError


class TestDockerImageScanner(unittest.TestCase):

    results = {
            "Results": [
                {"Vulnerabilities": [{"a_vulnerability": "whatever"}]}
            ]
    }

    @patch("docker.from_env")
    def test_can_scan_image(self, mocked_docker):
        image_id_to_scan = 'image_id_to_scan'
        mocked_docker.containers.run.return_value = json.dumps(self.results)
        volume_name = '/var/run/docker.sock'
        mount_path = '/var/run/docker.sock'
        expected_volumes = {volume_name: {'bind': mount_path, 'mode': 'rw'}}


        DockerImageScanner(mocked_docker).scan_image_for_vulnerabilities(image_id_to_scan)

        mocked_docker.containers.run.assert_called_once_with(
            'aquasec/trivy',
            f'-q --format json image {image_id_to_scan}',
            remove=True,
            volumes=expected_volumes
        )

    @patch("docker.from_env")
    def test_throw_exception_on_scan_error(self, mocked_docker):
        with pytest.raises(ScanError) as exception:
            image_id_to_scan = 'image_id_to_scan'
            mocked_docker.containers.run.side_effect = ContainerError(
                container=Mock(),
                image=Mock(),
                command="a command",
                stderr="a error on error output",
                exit_status=1
            )
            DockerImageScanner(mocked_docker).scan_image_for_vulnerabilities(image_id_to_scan)

        assert exception.value.message == "a error on error output"

    @patch("docker.from_env")
    def test_can_get_vulnerabilities_from_image(self, mocked_docker):
        image_id_having_vulnerabilities = 'image_id_to_scan'
        mocked_docker.containers.run.return_value = json.dumps(self.results)
        
        vulnerabilities = DockerImageScanner(mocked_docker).scan_image_for_vulnerabilities(
            image_id_having_vulnerabilities
        )

        assert vulnerabilities == [{"a_vulnerability": "whatever"}]


if __name__ == '__main__':
    unittest.main()
