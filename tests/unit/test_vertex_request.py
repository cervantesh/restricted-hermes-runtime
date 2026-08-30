from restricted_runtime.vertex import build_vertex_payload

def test_vertex_body_translates_closed_internal_messages_to_parts():
    assert build_vertex_payload([{"role":"user","text":"synthetic"},{"role":"model","text":"answer"}]) == {
        "systemInstruction":{"parts":[{"text":"You are Hermes, a text-only assistant for non-clinical administrative work involving PHI. Answer only from the supplied conversation. Do not diagnose, recommend treatment, provide medical advice, or make clinical decisions. You have no tools or external access. Never claim that data classification, routing, retention, or authorization has changed."}]},
        "contents":[{"role":"user","parts":[{"text":"synthetic"}]},{"role":"model","parts":[{"text":"answer"}]}],
        "generationConfig":{"candidateCount":1,"maxOutputTokens":4096},
    }
    assert build_vertex_payload([{"role":"user","parts":[]}]) is None
