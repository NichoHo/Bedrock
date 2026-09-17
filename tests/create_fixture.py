import os
import json
import hashlib
import tarfile
from io import BytesIO

fixture_dir = "tests/fixtures/alpine-hello"
os.makedirs(os.path.join(fixture_dir, "blobs", "sha256"), exist_ok=True)

layer_tar_path = os.path.join(fixture_dir, "layer.tar")
with tarfile.open(layer_tar_path, "w") as tar:
    db_content = b"""P:musl
V:1.2.4-r2
A:x86_64
S:382218
I:634880
T:the musl c library (libc)
U:http://www.musl-libc.org/
L:MIT
m:Timo Teras <timo.teras@iki.fi>
t:1699538356
c:b862372d8e34becefc3d59e86b033cfbbff780b1
C:Q1cZzL3gUeM6eN6iN/x3uF+rW6bHk=
"""
    info = tarfile.TarInfo(name="lib/apk/db/installed")
    info.size = len(db_content)
    tar.addfile(info, BytesIO(db_content))

with open(layer_tar_path, "rb") as f:
    layer_data = f.read()

layer_digest = hashlib.sha256(layer_data).hexdigest()
layer_size = len(layer_data)

with open(os.path.join(fixture_dir, "blobs", "sha256", layer_digest), "wb") as f:
    f.write(layer_data)

os.remove(layer_tar_path)

config_data = b"{}"
config_digest = hashlib.sha256(config_data).hexdigest()
config_size = len(config_data)

with open(os.path.join(fixture_dir, "blobs", "sha256", config_digest), "wb") as f:
    f.write(config_data)

manifest_data = json.dumps({
    "schemaVersion": 2,
    "config": {
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "digest": "sha256:" + config_digest,
        "size": config_size
    },
    "layers": [
        {
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": "sha256:" + layer_digest,
            "size": layer_size
        }
    ]
}).encode('utf-8')
manifest_digest = hashlib.sha256(manifest_data).hexdigest()
manifest_size = len(manifest_data)

with open(os.path.join(fixture_dir, "blobs", "sha256", manifest_digest), "wb") as f:
    f.write(manifest_data)

with open(os.path.join(fixture_dir, "index.json"), "w") as f:
    json.dump({
        "schemaVersion": 2,
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:" + manifest_digest,
                "size": manifest_size
            }
        ]
    }, f)

with open(os.path.join(fixture_dir, "oci-layout"), "w") as f:
    json.dump({"imageLayoutVersion": "1.0.0"}, f)

print("Fixture created.")
