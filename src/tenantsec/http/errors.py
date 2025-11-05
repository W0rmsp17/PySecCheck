class HttpError(Exception):
    def __init__(self, status: int, url: str, message: str = "", body_snippet: str = ""):
        super().__init__(message or f"HTTP {status} for {url}")
        self.status = status
        self.url = url
        self.body_snippet = body_snippet

class UnauthorizedError(HttpError): pass           # 401
class ForbiddenError(HttpError): pass              # 403
class NotFoundError(HttpError): pass               # 404
class ThrottleError(HttpError): pass               # 429
class ServerError(HttpError): pass                 # 5xx
class NetworkError(HttpError): pass                # request/timeout
