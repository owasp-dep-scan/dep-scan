import os
import shutil
import subprocess
import tarfile
import tempfile

import oras.client
import oras.provider
from oras.logger import setup_logger
from vdb.lib.config import data_dir

from depscan.lib.config import vdb_database_url, vdb_rafs_database_url
from depscan.lib.logger import LOG

setup_logger(quiet=True, debug=False)


class VdbDistributionRegistry(oras.provider.Registry):
    """
    We override the default registry to make things compatible with ghcr. Without this, the below error is thrown.

    jsonschema.exceptions.ValidationError: Additional properties are not allowed ('artifactType' was unexpected)
    """

    def get_manifest(self, container, allowed_media_type=None, refresh_headers=True):
        """
        Retrieve a manifest for a package.

        :param container:  parsed container URI
        :type container: oras.container.Container or str
        :param allowed_media_type: one or more allowed media types
        :type allowed_media_type: str
        """
        if not allowed_media_type:
            allowed_media_type = [oras.defaults.default_manifest_media_type]
        headers = {"Accept": ";".join(allowed_media_type)}

        get_manifest = f"{self.prefix}://{container.manifest_url()}"  # type: ignore
        response = self.do_request(get_manifest, "GET", headers=headers)
        self._check_200_response(response)
        manifest = response.json()
        return manifest


def download_rafs_based_image():
    """
    Method to download RAFS based vdb files from a oci registry
    """
    rafs_image_downloaded, paths_list = False, None
    nydus_image_command = shutil.which("nydus-image", mode=os.X_OK)
    if nydus_image_command is not None:
        LOG.info(
            "About to download the vulnerability database from %s. This might take a while ...",
            vdb_rafs_database_url,
        )

        try:
            oras_client = oras.client.OrasClient(
                registry=VdbDistributionRegistry()
            )
            rafs_data_dir = tempfile.TemporaryDirectory()
            paths_list = oras_client.pull(
                target=vdb_rafs_database_url,
                outdir=rafs_data_dir.name,
                allowed_media_type=[],
                overwrite=True,
            )

            if (
                paths_list
                and os.path.exists(
                    os.path.join(rafs_data_dir.name, "data.rafs")
                )
                and os.path.exists(
                    os.path.join(rafs_data_dir.name, "meta.rafs")
                )
            ):
                nydus_download_command = [
                    f"{nydus_image_command}",
                    "unpack",
                    "--blob",
                    os.path.join(rafs_data_dir.name, "data.rafs"),
                    "--output",
                    os.path.join(data_dir, "vdb.tar"),
                    "--bootstrap",
                    os.path.join(rafs_data_dir.name, "meta.rafs"),
                ]
                _ = subprocess.run(
                    nydus_download_command,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if os.path.exists(os.path.join(data_dir, "vdb.tar")):
                    rafs_image_downloaded = True
                    with tarfile.open(
                        os.path.join(data_dir, "vdb.tar"), "r"
                    ) as tarf:
                        tarf.extractall(path=data_dir)
                    os.remove(os.path.join(data_dir, "vdb.tar"))
                else:
                    raise FileNotFoundError("vdb.tar not found")
            else:
                raise FileNotFoundError("data.rafs or meta.rafs not found")

        except Exception:
            LOG.info(
                "Unable to pull the vulnerability database (rafs image) from %s. Trying to pull the non-rafs-based VDB image.",
                vdb_rafs_database_url,
            )
            rafs_image_downloaded = False

    return rafs_image_downloaded, data_dir


def download_image():
    """
    Method to download vdb files from a oci registry
    """
    rafs_image_downloaded, paths_list = download_rafs_based_image()
    if rafs_image_downloaded:
        return paths_list
    LOG.info(
        "About to download the vulnerability database from %s. This might take a while ...",
        vdb_database_url,
    )
    oras_client = oras.client.OrasClient(registry=VdbDistributionRegistry())
    paths_list = oras_client.pull(
        target=vdb_database_url,
        outdir=data_dir,
        allowed_media_type=[],
        overwrite=True,
    )
    for apath in paths_list:
        if apath.endswith(".tar.gz"):
            with tarfile.open(apath, "r") as tarf:
                tarf.extractall(path=data_dir)
            try:
                os.remove(apath)
            except OSError:
                pass
    return paths_list
