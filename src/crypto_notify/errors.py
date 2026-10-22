"""Exception types. Everything user-facing derives from CryptoNotifyError."""


class CryptoNotifyError(Exception):
    """Base class for errors the CLI reports without a traceback."""


class PortfolioError(CryptoNotifyError):
    """The portfolio file is missing or malformed."""


class PriceSourceError(CryptoNotifyError):
    """Prices or exchange rates could not be obtained."""


class NotifyError(CryptoNotifyError):
    """The report could not be delivered."""


class ConfigError(CryptoNotifyError):
    """Required configuration (API key, SMTP settings, ...) is missing or invalid."""
