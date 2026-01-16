"""Storage backends for scan results."""

from cyntrisec.storage.protocol import StorageBackend
from cyntrisec.storage.filesystem import FileSystemStorage
from cyntrisec.storage.memory import InMemoryStorage

__all__ = ["StorageBackend", "FileSystemStorage", "InMemoryStorage"]
