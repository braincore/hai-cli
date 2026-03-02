# Model Context Protocol

!!! warning "Experimental"
    MCP support is experimental and may change in future releases.

The [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) is an
open standard that enables AI assistants to connect with external tools and
data sources.

## Limitations

- **stdio-based MCPs only** - Network-based transports are not supported
- **Tools only** - Resources and prompts are not supported

## Adding an MCP Server

Use `/mcp-add` to register an MCP server:

```
/mcp-add <name> [<env>...] <cmd...>
```

- `<name>` - A unique identifier for the MCP server (used to invoke its tools)
- `<env>` - Optional environment variables in `KEY=VALUE` format
- `<cmd>` - The command to start the MCP server

### Examples

Add the Git MCP server:

```
/mcp-add ddg uvx -q duckduckgo-mcp-server
```

When an MCP server is added, the tool usage schema is added to the
conversation. This may consume a substantial number of tokens.

## Ask LLM to call an MCP

MCP tools can be called using the [!hai-tool](./tools.md#hai-tool-hai):

```
[1] !hai search "prusa core one indx release"

↓↓↓


- /mcp_ddg search {"query": "prusa core one indx release", "max_results": 10}


⚙ ⚙ ⚙

Pushed 1 command(s) into queue

---

!hai-tool[0]: /mcp_ddg search {"query": "prusa core one indx release", "max_results": 10}
[03/02/26 17:03:21] INFO     Processing request of type            server.py:720
                             CallToolRequest                                    
[03/02/26 17:03:22] INFO     HTTP Request: POST                  _client.py:1740
                             https://html.duckduckgo.com/html                   
                             "HTTP/1.1 200 OK"                                  
Found 10 search results:

1. Introducing the INDX! Fast and affordable 8-material printing ...

...
```

Note that the LLM called the MCP tool using the regular command `/mcp_ddg`,
which is discussed in the next section.

## Call MCP Tools Manually

Once registered, call MCP-tools using the dynamically created command:

```
/mcp_<name> <tool_name> <json_arg>
```

- `<name>` - The name you assigned when adding the MCP server
- `<tool_name>` - The name of the tool to invoke
- `<json_arg>` - A JSON object containing the tool's arguments
