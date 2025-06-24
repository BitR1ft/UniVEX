"""Tests for agent tools (query_graph, web_search)"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from app.agent.tools.query_graph_tool import QueryGraphTool
from app.agent.tools.web_search_tool import WebSearchTool


class TestQueryGraphTool:
    """Test QueryGraphTool"""
    
    def test_tool_initialization(self):
        """Test tool initialization"""
        tool = QueryGraphTool()
        assert tool.name == "query_graph"
        assert tool.user_id is None
        assert tool.project_id is None
    
    def test_tool_with_tenant_filtering(self):
        """Test tool with tenant filtering"""
        tool = QueryGraphTool(user_id="user123", project_id="project456")
        assert tool.user_id == "user123"
        assert tool.project_id == "project456"
    
    def test_convert_domain_query(self):
        """Test natural language to Cypher conversion for domains"""
        tool = QueryGraphTool()
        query = "Find all domains and their subdomains"
        cypher = tool._convert_to_cypher(query, 10)
        
        assert "Domain" in cypher
        assert "Subdomain" in cypher
        assert "LIMIT 10" in cypher
    
    def test_convert_vulnerability_query(self):
        """Test natural language to Cypher conversion for vulnerabilities"""
        tool = QueryGraphTool()
        query = "Find all high severity vulnerabilities"
        cypher = tool._convert_to_cypher(query, 10)
        
        assert "Vulnerability" in cypher
        assert "severity" in cypher or "LIMIT" in cypher
    
    def test_convert_port_query(self):
        """Test natural language to Cypher conversion for ports"""
        tool = QueryGraphTool()
        query = "Find all open ports for IP 10.0.0.1"
        cypher = tool._convert_to_cypher(query, 10)
        
        assert "Port" in cypher
        assert "open" in cypher
    
    def test_already_cypher_query(self):
        """Test that Cypher queries pass through"""
        tool = QueryGraphTool()
        query = "MATCH (n) RETURN n"
        cypher = tool._convert_to_cypher(query, 10)
        
        assert "MATCH" in cypher
        assert "RETURN" in cypher
    
    def test_add_tenant_filter(self):
        """Test tenant filter addition"""
        tool = QueryGraphTool(user_id="user123")
        query = "MATCH (n) RETURN n"
        filtered = tool._add_tenant_filter(query)
        
        assert "user123" in filtered or "user_id" in filtered
    
    def test_format_results(self):
        """Test result formatting"""
        tool = QueryGraphTool()
        records = [
            {"name": "example.com", "type": "domain"},
            {"name": "sub.example.com", "type": "subdomain"}
        ]
        
        output = tool._format_results(records, 10)
        assert "example.com" in output
        assert "sub.example.com" in output
        assert "2 result(s)" in output
    
    def test_format_empty_results(self):
        """Test formatting empty results"""
        tool = QueryGraphTool()
        output = tool._format_results([], 10)
        assert "No results found" in output


class TestWebSearchTool:
    """Test WebSearchTool"""
    
    def test_tool_initialization(self):
        """Test tool initialization"""
        tool = WebSearchTool()
        assert tool.name == "web_search"
    
    @pytest.mark.asyncio
    @patch.dict('os.environ', {}, clear=True)
    async def test_execute_without_api_key(self):
        """Test execution without API key"""
        tool = WebSearchTool()
        result = await tool.execute("test query")
        
        assert "Error" in result
        assert "TAVILY_API_KEY" in result
    
    def test_fallback_search(self):
        """Test fallback search"""
        tool = WebSearchTool()
        results = tool._fallback_search("test query", 5)
        
        assert len(results) > 0
        assert "title" in results[0]
        assert "url" in results[0]
    
    def test_format_results(self):
        """Test result formatting"""
        tool = WebSearchTool()
        results = [
            {
                "title": "Test Result",
                "url": "https://example.com",
                "content": "This is test content"
            }
        ]
        
        output = tool._format_results(results, "test query")
        assert "Test Result" in output
        assert "https://example.com" in output
        assert "test query" in output
    
    def test_format_empty_results(self):
        """Test formatting empty results"""
        tool = WebSearchTool()
        output = tool._format_results([], "test query")
        assert "No results found" in output
        assert "test query" in output
    
    def test_format_long_content(self):
        """Test formatting with long content"""
        tool = WebSearchTool()
        long_content = "a" * 300  # Content longer than 200 chars
        results = [
            {
                "title": "Test",
                "url": "https://example.com",
                "content": long_content
            }
        ]
        
        output = tool._format_results(results, "test")
        # Should be truncated with "..."
        assert "..." in output
        assert len(output) < len(long_content) + 100  # Reasonable size


@pytest.mark.asyncio
class TestToolIntegration:
    """Integration tests for tools"""
    
    @pytest.mark.skip(reason="Requires Neo4j connection")
    async def test_query_graph_execution(self):
        """Test actual graph query execution (requires Neo4j)"""
        tool = QueryGraphTool()
        result = await tool.execute("MATCH (n) RETURN n LIMIT 1")
        assert isinstance(result, str)
    
    @pytest.mark.skip(reason="Requires Tavily API key")
    async def test_web_search_execution(self):
        """Test actual web search execution (requires API key)"""
        tool = WebSearchTool()
        result = await tool.execute("CVE-2023-0001")
        assert isinstance(result, str)
