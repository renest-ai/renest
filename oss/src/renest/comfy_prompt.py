"""The one way renest hands a workflow to ComfyUI's ``/prompt``.

A recipe read back out of a finished picture can hold ``NaN``: ComfyUI writes
its metadata with Python's default ``json.dumps`` (which allows it), and some
custom nodes put ``NaN`` into their inputs at run time (seen 2026-10-07 as
``is_changed: nan``). httpx's ``json=`` refuses such values before anything is
sent ("Out of range float values are not JSON compliant"), so the test render
after a restore failed on a recipe ComfyUI itself accepts. Serialise here,
allowing ``NaN``, and send the bytes as they are.

A recipe read back from a picture is also the graph *after* ComfyUI processed it:
the editor sends a list-valued widget as ``{"__value__": [...]}`` so the server
does not mistake it for a link, and the server unwraps it before the graph is
written into the picture. Sent back as it is, ``"loras": []`` fails validation
("Bad linked input"), every output that depends on it is skipped, and the run
"succeeds" with nothing saved (seen 2026-10-07 on two community workflows). So a
list that is not a link to another node in the same graph is wrapped again,
exactly as the editor would send it.
"""

from __future__ import annotations

import json

HEADERS = {"Content-Type": "application/json"}


def _is_link(value, node_ids: set[str]) -> bool:
    """``[node_id, slot]`` pointing at a node of this graph -- ComfyUI's link shape."""
    return (isinstance(value, list) and len(value) == 2
            and isinstance(value[0], (str, int)) and not isinstance(value[0], bool)
            and str(value[0]) in node_ids
            and isinstance(value[1], int) and not isinstance(value[1], bool))


def as_editor_sends(graph: dict) -> dict:
    """The graph with list-valued widget inputs wrapped the way the editor sends them.

    Links stay as they are; a value already wrapped stays as it is. Nothing else in
    the recipe changes.
    """
    ids = {str(k) for k in graph}
    out = {}
    for nid, node in graph.items():
        if not isinstance(node, dict) or not isinstance(node.get("inputs"), dict):
            out[nid] = node
            continue
        inputs = {}
        for name, value in node["inputs"].items():
            if isinstance(value, list) and not _is_link(value, ids):
                value = {"__value__": value}
            inputs[name] = value
        out[nid] = {**node, "inputs": inputs}
    return out


def prompt_body(graph: dict, editor: dict | None = None) -> bytes:
    """The ``/prompt`` request body for this node graph: ``NaN`` passed through,
    list-valued widgets wrapped as the editor sends them, and -- when the nest
    carries the editor-form workflow -- that workflow attached the way the editor
    attaches it, because some nodes read their settings from it at run time."""
    body: dict = {"prompt": as_editor_sends(graph)}
    if isinstance(editor, dict) and isinstance(editor.get("nodes"), list):
        body["extra_data"] = {"extra_pnginfo": {"workflow": editor}}
    return json.dumps(body, allow_nan=True).encode("utf-8")
