"""Exceptions for Qualys."""


class QualysException(Exception):
  """Base exception class for QualysException."""


class QualysApiException(QualysException):
  """Exception raised when we get an error response from Qualys API."""

  def __init__(self, status_code, message):
    """Init QualysApiException."""
    self.status_code = status_code
    self.message = message


class QualysUserException(QualysException):
  """Exception raised when a uiIdentityId that doesn't exist is given."""

  def __init__(self, uiIdentityId):
    """Init QualysUserException."""
    self.uiIdentityId = uiIdentityId

class NVDApiException(QualysException):
  """Exception raised when we get an error response from NVD API."""

  def __init__(self, status_code, message):
    """Init NVDApiException."""
    self.status_code = status_code
    self.message = message