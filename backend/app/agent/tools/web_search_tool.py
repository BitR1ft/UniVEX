"""
Web Search Tool

Tool for searching the web using Tavily API for CVE research and information gathering.
"""

from app.agent.tools.base_tool import BaseTool, ToolMetadata
import logging
import os

logger = logging.getLogger(__name__)


class WebSearchTool(BaseTool):
    """
    Tool for searching the web using Tavily API.
    
    Useful for:
    - CVE research
    - Vulnerability information
    - Exploit details
    - Technology documentation
    """
    
    def __init__(self):
        """Initialize WebSearchTool"""
        super().__init__()
        self.api_key = os.getenv("TAVILY_API_KEY", "")
    
    def _define_metadata(self) -> ToolMetadata:
        """Define tool metadata"""
        return ToolMetadata(
            name="web_search",
            description="""Search the web for information about vulnerabilities, CVEs, exploits, and security topics.
            
Examples:
- "CVE-2023-1234 details and exploits"
- "Apache Struts vulnerability information"
- "How to exploit SQL injection in MySQL"
- "Latest WordPress security vulnerabilities"
            
Returns web search results with titles, URLs, and snippets.""",
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query"
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of results (default: 5)",
                        "default": 5
                    },
                    "search_depth": {
                        "type": "string",
                        "description": "Search depth: basic or advanced (default: basic)",
                        "enum": ["basic", "advanced"],
                        "default": "basic"
                    }
                },
                "required": ["query"]
            }
        )
    
    async def execute(self, query: str, max_results: int = 5, search_depth: str = "basic", **kwargs) -> str:
        """
        Execute web search.
        
        Args:
            query: Search query
            max_results: Maximum results
            search_depth: Search depth (basic or advanced)
            
        Returns:
            Search results as formatted string
        """
        try:
            if not self.api_key:
                return "Error: TAVILY_API_KEY not configured. Please set the environment variable."
            
            # Use Tavily API
            results = await self._search_tavily(query, max_results, search_depth)
            
            if not results:
                return f"No results found for query: {query}"
            
            return self._format_results(results, query)
            
        except Exception as e:
            logger.error(f"Web search error: {e}", exc_info=True)
            return f"Error executing search: {str(e)}"
    
    async def _search_tavily(self, query: str, max_results: int, search_depth: str) -> list:
        """
        Search using Tavily API.
        
        Args:
            query: Search query
            max_results: Maximum results
            search_depth: Search depth
            
        Returns:
            List of search results
        """
        try:
            from tavily import AsyncTavilyClient
            
            client = AsyncTavilyClient(api_key=self.api_key)
            
            response = await client.search(
                query=query,
                search_depth=search_depth,
                max_results=max_results
            )
            
            return response.get("results", [])
            
        except ImportError:
            # Fallback to sync client if async not available
            logger.warning("AsyncTavilyClient not available, using sync client")
            from tavily import TavilyClient
            
            client = TavilyClient(api_key=self.api_key)
            
            response = client.search(
                query=query,
                search_depth=search_depth,
                max_results=max_results
            )
            
            return response.get("results", [])
        
        except Exception as e:
            logger.error(f"Tavily API error: {e}", exc_info=True)
            
            # Fallback to basic search simulation for development
            return self._fallback_search(query, max_results)
    
    def _fallback_search(self, query: str, max_results: int) -> list:
        """
        Fallback search when Tavily is not available.
        
        Args:
            query: Search query
            max_results: Maximum results
            
        Returns:
            Mock search results
        """
        logger.warning("Using fallback search (Tavily API not available)")
        
        # Return mock results for development
        return [
            {
                "title": f"Search result for: {query}",
                "url": "https://example.com/result",
                "content": f"This is a fallback result. Tavily API is not configured. Query: {query}",
                "score": 0.9
            }
        ]
    
    def _format_results(self, results: list, query: str) -> str:
        """
        Format search results for display.
        
        Args:
            results: Search results
            query: Original query
            
        Returns:
            Formatted string
        """
        if not results:
            return f"No results found for: {query}"
        
        output = f"Web search results for '{query}':\n\n"
        
        for i, result in enumerate(results, 1):
            title = result.get("title", "No title")
            url = result.get("url", "")
            content = result.get("content", "")
            
            output += f"{i}. {title}\n"
            output += f"   URL: {url}\n"
            
            # Truncate content
            if content:
                content_preview = content[:200] + "..." if len(content) > 200 else content
                output += f"   {content_preview}\n"
            
            output += "\n"
        
        return output
