from importlib.metadata import version
import toml

try:
    with open("pyproject.toml", mode="r") as config:
        toml_file = toml.load(config)
    __version__ = toml_file["project"]["version"]
    __appname__ = "octuho" + __version__.split(".")[0]
    __appabbr__ = "oct" + __version__.split(".")[0]
    __startmode__ = "dev"
except Exception as e:
    print("error: " + str(e))
    __startmode__ = "systemd"
    __appname__ = "octuho"
    __appabbr__ = "oct"
    __version__ = version(__appname__)