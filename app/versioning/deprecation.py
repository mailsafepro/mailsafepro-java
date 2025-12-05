"""
API Deprecation Utilities
"""

from fastapi import Response
from datetime import datetime
from typing import Optional

def deprecate_endpoint(
    response: Response,
    sunset_date: Optional[datetime] = None,
    link: Optional[str] = None
):
    """
    Add Deprecation and Sunset headers to response.
    
    Args:
        response: FastAPI Response object
        sunset_date: When the endpoint will be removed (Sunset header)
        link: Link to migration guide (Link header)
    """
    # RFC 8594: Deprecation: <date> or "true"
    response.headers["Deprecation"] = "true"
    
    if sunset_date:
        # RFC 8594: Sunset: <HTTP-date>
        response.headers["Sunset"] = sunset_date.strftime("%a, %d %b %Y %H:%M:%S GMT")
        
    if link:
        response.headers["Link"] = f'<{link}>; rel="deprecation"; type="text/html"'

class DeprecationDependency:
    """
    Dependency to mark an endpoint as deprecated.
    
    Usage:
        @router.get("/old", dependencies=[Depends(DeprecationDependency(sunset_date=...))])
    """
    def __init__(self, sunset_date: Optional[datetime] = None, link: Optional[str] = None):
        self.sunset_date = sunset_date
        self.link = link

    async def __call__(self, response: Response):
        deprecate_endpoint(response, self.sunset_date, self.link)
