from typing import Protocol


class PlatformAdapter(Protocol):
    name: str

    def sync_programs(self, conn, cfg) -> int:
        """Fetch program directory + scope from the platform API and upsert.

        NOTE: these calls hit the *platform's* public management API with the
        researcher's own credentials — they are NOT target traffic, so the
        per-program request budget does not apply. Target traffic must always
        go through HardenedClient.
        """
        ...


REGISTRY: dict[str, type] = {}


def register(cls):
    REGISTRY[cls.name] = cls
    return cls
