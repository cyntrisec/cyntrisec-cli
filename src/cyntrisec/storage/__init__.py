"""Storage backends for scan results."""

from cyntrisec.storage.filesystem import FileSystemStorage
from cyntrisec.storage.memory import InMemoryStorage
from cyntrisec.storage.protocol import StorageBackend

__all__ = ["StorageBackend", "FileSystemStorage", "InMemoryStorage"]
