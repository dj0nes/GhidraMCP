# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def _program_query(program: str | None) -> dict:
    """Query-string dict carrying the optional program selector."""
    return {"program": program} if program else {}

def safe_get(endpoint: str, params: dict = None, program: str = None) -> list:
    """
    Perform a GET request with optional query parameters.
    program, when given, selects an open program by name or project path
    instead of the active CodeBrowser tab.
    """
    params = dict(params or {})
    params.update(_program_query(program))

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str, program: str = None) -> str:
    """
    Perform a POST request with a form or raw body.

    Endpoints that modify the program save it to disk before replying (the plugin's
    auto-save), so the timeout leaves room for a save on a large program. The reply
    ends with "; saved" or "; SAVE FAILED: <reason>" when a change was committed.
    """
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, params=_program_query(program), timeout=30)
        else:
            response = requests.post(url, data=data.encode("utf-8"),
                                     params=_program_query(program), timeout=30)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

def safe_post_json(endpoint: str, json_data, program: str = None) -> str:
    """
    Perform a POST request with a JSON body.

    As with safe_post, a committed change is saved to disk before the reply and the
    reply ends with "; saved" or "; SAVE FAILED: <reason>".
    """
    import json
    try:
        url = urljoin(ghidra_server_url, endpoint)
        body = json.dumps(json_data) if not isinstance(json_data, str) else json_data
        response = requests.post(url, data=body.encode("utf-8"),
                                 params=_program_query(program),
                                 headers={"Content-Type": "application/json"},
                                 timeout=30)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit}, program=program)

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit}, program=program)

@mcp.tool()
def decompile_function(name: str, program: str = None) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name, program=program)

@mcp.tool()
def rename_function(old_name: str, new_name: str, program: str = None) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name}, program=program)

@mcp.tool()
def rename_data(address: str, new_name: str, program: str = None) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name}, program=program)

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit}, program=program)

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit}, program=program)

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit}, program=program)

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit}, program=program)

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit}, program=program)

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit}, program=program)

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str, program: str = None) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    }, program=program)

@mcp.tool()
def get_function_by_address(address: str, program: str = None) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}, program=program))

@mcp.tool()
def get_current_address(program: str = None) -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address", program=program))

@mcp.tool()
def get_current_function(program: str = None) -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function", program=program))

@mcp.tool()
def list_functions(program: str = None) -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions", program=program)

@mcp.tool()
def decompile_function_by_address(address: str, program: str = None) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}, program=program))

@mcp.tool()
def disassemble_function(address: str, program: str = None) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address}, program=program)

@mcp.tool()
def set_decompiler_comment(address: str, comment: str, program: str = None) -> str:
    """
    Set a comment for a given address in the function pseudocode (a PRE comment).
    The comment must contain text: an empty or whitespace-only comment is rejected
    (it would be stored as a blank comment and show as an empty block). To remove a
    comment use delete_comment.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment}, program=program)

@mcp.tool()
def set_disassembly_comment(address: str, comment: str, program: str = None) -> str:
    """
    Set a comment for a given address in the function disassembly (an EOL comment).
    The comment must contain text: an empty or whitespace-only comment is rejected.
    To remove a comment use delete_comment.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment}, program=program)

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str, program: str = None) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name}, program=program)

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str, program: str = None) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype}, program=program)

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str, program: str = None) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type}, program=program)

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit}, program=program)

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit}, program=program)

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit}, program=program)

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None, program: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params, program=program)

@mcp.tool()
def clear_data(address: str, size: int = None, program: str = None) -> str:
    """
    Clear (undefine) data at an address, reverting bytes to undefined state.
    If size is omitted, clears the single data item at that address.
    """
    data = {"address": address}
    if size is not None:
        data["size"] = str(size)
    return safe_post("clear_data", data, program=program)

@mcp.tool()
def define_data(address: str, data_type: str, label: str = None, program: str = None) -> str:
    """
    Create a data definition at an address. Supported types: byte, word, dword, qword,
    float, double, pointer, char, or any type in the data type manager.
    Optionally assign a label/symbol name.
    """
    data = {"address": address, "data_type": data_type}
    if label:
        data["label"] = label
    return safe_post("define_data", data, program=program)

@mcp.tool()
def define_data_batch(items: list[dict], program: str = None) -> str:
    """
    Create multiple data definitions in a single transaction.
    Each item: {"address": "0x...", "data_type": "dword", "label": "optional_name"}
    """
    return safe_post_json("define_data_batch", items, program=program)

@mcp.tool()
def read_bytes(address: str, length: int, program: str = None) -> str:
    """
    Read raw bytes from memory at a given address. Returns hex-encoded string.
    """
    return safe_get("read_bytes", {"address": address, "length": length}, program=program)

@mcp.tool()
def get_data_at(address: str, program: str = None) -> str:
    """
    Get detailed info about the data item at a specific address:
    type, size, label, value, and containing item info.
    """
    return safe_get("get_data_at", {"address": address}, program=program)

@mcp.tool()
def batch_rename_functions(renames: list[dict], program: str = None) -> str:
    """
    Rename multiple functions in one transaction.
    Each item: {"address": "0x...", "new_name": "MyFunction"}
    """
    return safe_post_json("batch_rename_functions", renames, program=program)

@mcp.tool()
def get_comments(address: str, program: str = None) -> list:
    """
    Read every comment at one address: pre, post, eol, plate and repeatable, each
    labelled. A type with no comment shows "(none)"; a comment stored as an empty
    string shows "(EMPTY STRING ...)" and a whitespace-only one "(WHITESPACE ONLY ...)",
    so a blank comment is never mistaken for no comment. At a function's entry point
    the function header comment is the plate comment (the same stored value), and a
    note says so.
    """
    return safe_get("get_comments", {"address": address}, program=program)

@mcp.tool()
def list_comments(start: str = None, end: str = None, function: str = None,
                  offset: int = 0, limit: int = 100, program: str = None) -> list:
    """
    List all comments in an address range or a function body, one line per comment as
    "<address> <type>: "<text>"", sorted by address. Give either start and end
    (inclusive), or function (the address of, or any address inside, a function).
    Empty/whitespace-only comments are flagged. Paged with offset/limit.
    """
    params = {"offset": offset, "limit": limit}
    if function:
        params["function"] = function
    else:
        if start:
            params["start"] = start
        if end:
            params["end"] = end
    return safe_get("list_comments", params, program=program)

@mcp.tool()
def delete_comment(address: str, comment_type: str, program: str = None) -> str:
    """
    Delete a comment (sets it to null, which removes it entirely; this is how to remove
    a blank comment too). comment_type: pre (the decompiler comment), post, eol (the
    disassembly comment), plate, repeatable, or all. Reports exactly what was deleted,
    or that nothing was there (in which case nothing is changed or saved). The function
    header comment is the plate comment at the function's entry point, so
    comment_type=plate removes it.
    """
    return safe_post("delete_comment", {"address": address, "comment_type": comment_type}, program=program)

@mcp.tool()
def batch_set_comments(comments: list[dict], comment_type: str = "decompiler", program: str = None) -> str:
    """
    Set multiple comments in one transaction.
    comment_type: "decompiler" (PRE_COMMENT) or "disassembly" (EOL_COMMENT).
    Each comment: {"address": "0x...", "comment": "text"}
    Entries with an empty or whitespace-only comment are rejected (counted as failed);
    use delete_comment to remove a comment.
    """
    return safe_post_json("batch_set_comments", {
        "comment_type": comment_type,
        "comments": comments
    }, program=program)

@mcp.tool()
def create_label(address: str, name: str, namespace: str = None, program: str = None) -> str:
    """
    Create a label/symbol at any address (code, data, or undefined bytes).
    """
    data = {"address": address, "name": name}
    if namespace:
        data["namespace"] = namespace
    return safe_post("create_label", data, program=program)

@mcp.tool()
def create_enum(name: str, values: list[dict], size: int = 4, program: str = None) -> str:
    """
    Create an enum data type. Each value: {"name": "MEMBER_NAME", "value": 0}
    """
    return safe_post_json("create_enum", {
        "name": name,
        "size": size,
        "values": values
    }, program=program)

@mcp.tool()
def create_struct(name: str, fields: list[dict], program: str = None) -> str:
    """
    Create a structure data type.
    Each field: {"name": "field_name", "type": "int", "size": 4}
    If size is omitted, the type's natural size is used.
    """
    return safe_post_json("create_struct", {
        "name": name,
        "fields": fields
    }, program=program)

@mcp.tool()
def apply_struct(address: str, struct_name: str, program: str = None) -> str:
    """
    Apply a previously created struct type at a memory address.
    Clears existing data at the address range and stamps the struct.
    """
    return safe_post("apply_struct", {"address": address, "struct_name": struct_name}, program=program)

@mcp.tool()
def delete_data_type(name: str, program: str = None) -> str:
    """
    Delete a struct, enum, or other data type from the program's type manager.
    Anything already applied in the listing reverts to undefined bytes.
    """
    return safe_post("delete_data_type", {"name": name}, program=program)

@mcp.tool()
def save_program(program: str = None) -> str:
    """
    Save the current program to its project file. Every tool that modifies the
    program already saves automatically (the reply ends with "; saved" or
    "; SAVE FAILED: <reason>"), so this is only needed after changes made outside
    this API, or when auto-save has been turned off in the plugin's tool options.
    """
    return safe_post("save_program", "", program=program)

@mcp.tool()
def list_open_programs() -> list:
    """
    List every program open in any CodeBrowser window, one per line:
    name, project path, language:compiler, then "(active)" for the serving
    window's front tab or "(other window: NAME)" for programs open elsewhere.
    Pass the name or the project path as the program argument of any other tool
    to work on that program without switching tabs.
    """
    return safe_get("list_open_programs")

@mcp.tool()
def switch_tab(program: str) -> str:
    """
    Bring an open program's tab to the front (by name or project path).
    Only needed for get_current_address / get_current_function, which follow the
    GUI cursor; every other tool takes a program argument directly.
    """
    return safe_post("switch_tab", {"program": program})

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

