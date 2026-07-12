from __future__ import annotations

import keyring
from keyring.errors import KeyringError

SERVICE_NAME = "EagleEyeSOCPlatform"


class SecretStoreError(RuntimeError):
    pass


class SecretStore:
    def get(self, key: str) -> str:
        try:
            return keyring.get_password(SERVICE_NAME, key) or ""
        except KeyringError as exc:
            raise SecretStoreError(str(exc)) from exc

    def set(self, key: str, value: str) -> None:
        try:
            if value:
                keyring.set_password(SERVICE_NAME, key, value)
            else:
                try:
                    keyring.delete_password(SERVICE_NAME, key)
                except KeyringError:
                    pass
        except KeyringError as exc:
            raise SecretStoreError(str(exc)) from exc
